const express = require("express");
const multer = require("multer");
const path = require("path");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const fs = require("fs");
const cors = require("cors");
const { body, validationResult } = require("express-validator");
const sanitizeFilename = require("sanitize-filename");
const axios = require("axios");
const FormData = require("form-data");
require("dotenv").config();

const app = express();
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 1024 * 1024 * 1024 * 5 }, // Limit file size to 5GB to make sure accidents don't happen
});

const STATIC_BASE_DIR = path.join(__dirname, "static");
fs.mkdir(STATIC_BASE_DIR, { recursive: true }, (err) => {
  if (err) {
    console.error("Error creating static directory:", err);
  }
});

const staticUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const folderPath = path.join(STATIC_BASE_DIR, req.params.folder);

      // Use the callback-based `fs.mkdir` method
      fs.mkdir(folderPath, { recursive: true }, (err) => {
        if (err) {
          return cb(err, null); // Pass the error to multer
        }
        cb(null, folderPath); // Pass the folder path to multer
      });
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
      cb(
        null,
        file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
      );
    },
  }),
  limits: { fileSize: 1024 * 1024 * 1024 * 5 }, // 5GB file size limit (same as up)
});

const secrets = require("./config.js");

const {
  dbConfig,
  jwtSecret,
  version,
  serverName,
  serverURL,
  port,
  copyrightHolder,
  corsOrigin,
  enableSyncing,
  isSlave,
  masterServerURL,
  slaveServerURL,
} = secrets;

app.use(express.json());
app.use(cors({ origin: corsOrigin }));

const pool = mysql.createPool(dbConfig);

// Test the database connection
pool.getConnection((err, connection) => {
  if (err) {
    console.error("Error connecting to database:", err);
  } else {
    console.log("Connected to MariaDB database");
    connection.release(); // Release the connection back to the pool
  }
});

const generateToken = (userId) => {
  // Customize the payload as needed (e.g., include user roles or permissions)
  const payload = { userId };
  return jwt.sign(payload, jwtSecret, { expiresIn: "1h" }); // Token expires in 1 hour
};

// Authentication middleware
const authenticate = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1]; // Get token from Authorization header

  if (!token) {
    return res.status(401).send("Authorization token missing.");
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    req.userId = decoded.userId; // Make userId available in the request object
    next();
  } catch (error) {
    res.status(401).send("Invalid token.");
  }
};

// Middleware to authenticate the /sync endpoint
function syncAuthenticate(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (token !== process.env.SHARED_SECRET) {
    return res.status(403).send("Unauthorized.");
  }
  next();
}

// API endpoint for syncing files (slave server only)
app.post("/sync", syncAuthenticate, upload.single("file"), (req, res) => {
  if (!isSlave || !enableSyncing) {
    return res
      .status(403)
      .send("Sync route is not available on the master server.");
  }

  if (!req.file) {
    return res.status(400).send("No file received.");
  }

  const { path: tempPath, originalname } = req.file;
  const savePath = path.join(__dirname, "uploads", originalname);

  // Extract the additional metadata from the request body
  const { fileId, userId, filename } = req.body;

  // Validate received data
  if (!fileId || !userId || !filename) {
    return res.status(400).send("Missing required metadata.");
  }

  console.log(
    "Should insert file ID " +
      fileId +
      " with user ID " +
      userId +
      " and filename " +
      filename
  );

  // Move the file to the /uploads directory
  fs.rename(tempPath, savePath, (err) => {
    if (err) {
      console.error("Error saving file:", err);
      return res.status(500).send("Error saving file.");
    }

    // After moving the file, store file metadata in the slave's database
    const fileKey = path.basename(savePath);

    // Sanitize the filename to remove problematic characters
    const sanitizedFilename = sanitizeFilename(filename);
    if (!sanitizedFilename) {
      return res.status(400).send("Invalid filename.");
    }

    // Store file metadata in the slave's database (use the same pool logic as the master)
    const query =
      "INSERT INTO files (userId, filename, path, fileKey, fileId) VALUES (?, ?, ?, ?, ?)";
    pool.execute(
      query,
      [userId, sanitizedFilename, savePath, fileKey, fileId],
      (err, results) => {
        if (err) {
          console.error("Error saving file metadata to database:", err);
          return res.status(500).send("Error saving file metadata.");
        }

        res
          .status(200)
          .send(`File ${originalname} received, saved, and metadata stored.`);
      }
    );
  });
});

// API endpoint for file uploads (protected by authentication)
app.post("/upload", authenticate, upload.single("file"), async (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  if (!req.file) {
    return res.status(400).send("No file uploaded.");
  }

  const { originalname, path: filepath } = req.file;
  const userId = req.userId;

  // Extract the file key from the multer-generated filepath
  const fileKey = path.basename(filepath);

  // Sanitize the filename to remove problematic characters
  const sanitizedFilename = sanitizeFilename(originalname);
  if (!sanitizedFilename) {
    return res.status(400).send("Invalid filename.");
  }

  // Store file metadata in the database (including the file key)
  const query =
    "INSERT INTO files (userId, filename, path, fileKey) VALUES (?, ?, ?, ?)";
  pool.execute(
    query,
    [userId, sanitizedFilename, filepath, fileKey],
    async (err, results) => {
      if (err) {
        console.error("Error saving file metadata to database:", err);
        return res.status(500).send("Error uploading file.");
      }

      const fileId = results.insertId;

      // Prepare data for syncing to the slave server
      const form = new FormData();
      form.append("file", fs.createReadStream(filepath), fileKey);
      form.append("fileId", fileId); // Pass fileId
      form.append("userId", userId); // Pass userId
      form.append("filename", sanitizedFilename); // Pass sanitized filename

      if (enableSyncing) {
        try {
          const response = await axios.post(slaveServerURL + "/sync", form, {
            headers: {
              ...form.getHeaders(),
              Authorization: `Bearer ${process.env.SHARED_SECRET}`, // Shared secret
            },
          });
          console.log("Sync response:", response.data);
        } catch (syncErr) {
          console.error("Error syncing file to slave server:", syncErr);
        }

        // Return a JSON response with fileId and fileKey
        res.status(200).json({
          fileId: fileId,
          fileKey: fileKey,
        });
      }
    }
  );
});

// API endpoint to get files by a specific user
app.get("/files/user/:userId", authenticate, (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  const userId = req.params.userId;

  const query = "SELECT * FROM files WHERE userId = ?";

  pool.execute(query, [userId], (err, results) => {
    if (err) {
      console.error("Error fetching files from database:", err);
      return res.status(500).send("Error fetching files.");
    }
    res.json(results);
  });
});

app.get("/files/:fileId", authenticate, (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  const fileId = parseInt(req.params.fileId);
  if (isNaN(fileId)) {
    return res.status(400).send("Invalid file ID.");
  }
  const query = `
        SELECT 
            f.path,
            u.username AS user 
        FROM files f
        JOIN users u ON f.userId = u.id
        WHERE f.id = ?`;

  pool.execute(query, [fileId], (err, results) => {
    if (err) {
      console.error("Error fetching file details:", err);
      return res.status(500).send("Error getting file details.");
    }

    if (results.length === 0) {
      return res.status(404).send("File not found.");
    }

    const { path, user } = results[0];

    fs.stat(path, (err, stats) => {
      if (err) {
        console.error("Error getting file stats:", err);
        return res.status(500).send("Error getting file details.");
      }

      const key = path.split("/").pop(); // Extract key from the path

      const fileDetails = {
        key,
        user,
        date: stats.mtime,
        size: stats.size,
      };

      res.json(fileDetails);
    });
  });
});

// API endpoint to delete a specific file
app.delete("/files/:fileId", authenticate, (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  const fileId = parseInt(req.params.fileId);
  if (isNaN(fileId)) {
    return res.status(400).send("Invalid file ID.");
  }

  const query = `
        SELECT 
            f.path,
            u.username AS user,
            f.userId
        FROM files f
        JOIN users u ON f.userId = u.id
        WHERE f.id = ?`;

  pool.execute(query, [fileId], (err, results) => {
    if (err) {
      console.error("Error fetching file path from database:", err);
      return res.status(500).send("Error deleting file.");
    }

    if (results.length === 0) {
      return res.status(404).send("File not found.");
    }

    const fileUserId = results[0].userId;
    if (fileUserId !== req.userId) {
      return res
        .status(403)
        .send(
          "Forbidden. You do not have permission to delete this file: " +
            fileUserId +
            " " +
            req.userId
        );
    }

    const filepath = results[0].path;

    // Delete the file from the database
    const deleteQuery = "DELETE FROM files WHERE id = ?";
    pool.execute(deleteQuery, [fileId], (err, results) => {
      if (err) {
        console.error("Error deleting file from database:", err);
        return res.status(500).send("Error deleting file.");
      }

      // Delete the file from the file system
      fs.unlink(filepath, (err) => {
        if (err) {
          console.error("Error deleting file from file system:", err);
        }
        res.send("File deleted successfully!");
      });
    });
  });
});

app.get("/files/:fileId/embed", (req, res) => {
  const fileId = parseInt(req.params.fileId);
  if (isNaN(fileId)) {
    return res.status(400).send("Invalid file ID.");
  }

  const query = isSlave
    ? "SELECT filename, path FROM files WHERE fileId = ?"
    : "SELECT filename, path FROM files WHERE id = ?";

  pool.execute(query, [fileId], (err, results) => {
    // Check for database errors
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).send("Database error occurred.");
    }

    // Check if no results were found
    if (!results || results.length === 0) {
      return res.status(404).send("File not found.");
    }

    // Safely destructure results
    const { filename, path: filepath } = results[0];

    // Additional validation
    if (!filename || !filepath) {
      return res.status(500).send("Invalid file information.");
    }

    // Safely resolve path
    let absolutePath;
    try {
      absolutePath = path.resolve(filepath);
    } catch (pathErr) {
      console.error("Path resolution error:", pathErr);
      return res.status(500).send("Error processing file path.");
    }

    // Determine content type
    const extname = path.extname(filename).toLowerCase();
    const contentTypeMap = {
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".png": "image/png",
      ".gif": "image/gif",
      ".mp4": "video/mp4",
      ".webm": "video/webm",
      ".ogg": "video/ogg",
    };

    const contentType = contentTypeMap[extname] || "application/octet-stream";

    // create file stream
    let fileStream;
    try {
      fileStream = fs.createReadStream(absolutePath);
    } catch (readErr) {
      console.error("File read error:", readErr);
      return res.status(500).send("Error reading file.");
    }

    fileStream.on("error", (streamErr) => {
      console.error("File stream error:", streamErr);
      if (!res.headersSent) {
        res.status(500).send("Error streaming file.");
      }
    });

    res.setHeader("Content-Type", contentType);
    res.setHeader("Access-Control-Allow-Origin", "*");

    fileStream.pipe(res).on("error", (pipeErr) => {
      console.error("Pipe error:", pipeErr);
      if (!res.headersSent) {
        res.status(500).send("Error streaming file.");
      }
    });
  });
});

// API endpoint to download a file
app.get("/files/:fileId/download", (req, res) => {
  const fileId = parseInt(req.params.fileId);
  if (isNaN(fileId)) {
    return res.status(400).send("Invalid file ID.");
  }
  var query = "";
  if (isSlave) {
    query = "SELECT filename, path FROM files WHERE fileId = ?";
  } else {
    query = "SELECT filename, path FROM files WHERE id = ?";
  }
  pool.execute(query, [fileId], (err, results) => {
    if (err) {
      console.error("Error fetching file from database:", err);
      return res.status(500).send("Error downloading file.");
    }
    if (results.length === 0) {
      return res.status(404).send("File not found.");
    }
    const { filename, path: filepath } = results[0];
    res.download(filepath, filename);
  });
});

// API endpoint to rename a file by ID (only in the database)
app.put(
  "/files/:fileId/rename",
  authenticate,
  // Input validation using express-validator
  body("newFilename")
    .notEmpty()
    .withMessage("New filename is required")
    .isLength({ min: 1, max: 100 })
    .withMessage("Filename must be between 1 and 100 characters")
    .matches(/^[a-zA-Z0-9_.-]+$/)
    .withMessage("Filename contains invalid characters"),

  (req, res) => {
    const fileId = parseInt(req.params.fileId);
    if (isNaN(fileId)) {
      return res.status(400).send("Invalid file ID.");
    }

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { newFilename } = req.body;

    const query = "SELECT filename FROM files WHERE id = ?";
    pool.execute(query, [fileId], (err, results) => {
      if (isSlave) {
        return res.status(403).send("Please query the master server.");
      }
      if (err) {
        console.error("Error fetching file from database:", err);
        return res.status(500).send("Error renaming file.");
      }

      if (results.length === 0) {
        return res.status(404).send("File not found.");
      }

      const fileUserId = results[0].userId;
      if (fileUserId !== req.userId) {
        return res
          .status(403)
          .send("Forbidden. You do not have permission to rename this file.");
      }

      // Update the file name in the database (without modifying the file on disk)
      const updateQuery = "UPDATE files SET filename = ? WHERE id = ?";
      pool.execute(updateQuery, [newFilename, fileId], (updateErr) => {
        if (updateErr) {
          console.error("Error updating filename in database:", updateErr);
          return res.status(500).send("Error updating filename in database.");
        }

        res.status(200).send("File renamed successfully in the database.");
      });
    });
  }
);

app.get("/user/id/:username", authenticate, (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }
  const username = req.params.username;
  const query = "SELECT id FROM users WHERE username = ?";

  pool.execute(query, [username], (err, results) => {
    if (err) {
      console.error("Error querying database:", err);
      return res.status(500).send("Error retrieving user ID.");
    }

    if (results.length > 0) {
      const userId = results[0].id;
      res.send({ userId });
    } else {
      res.status(404).send("User not found.");
    }
  });
});

app.post("/login", (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }
  const { username, password } = req.body;
  const query = "SELECT id FROM users WHERE username = ? AND password = ?";

  pool.execute(query, [username, password], (err, results) => {
    if (err) {
      console.error("Error querying database:", err);
      return res.status(500).send("Error during login: " + err.message);
    }

    if (results.length > 0) {
      const userId = results[0].id;
      const token = generateToken(userId);
      res.send({ token });
    } else {
      res.status(401).send("Invalid credentials.");
    }
  });
});

// API endpoint for public file access with preview and download
app.get("/public/:fileKey", (req, res) => {
  const fileKey = req.params.fileKey;
  var query = "";
  if (isSlave) {
    query =
      "SELECT f.fileId, f.filename, f.path FROM files f WHERE f.fileKey = ?";
  } else {
    query =
      'SELECT f.id, f.filename, f.path, u.username FROM files f JOIN users u ON f.userId = u.id WHERE f.path LIKE CONCAT("uploads/", ?, "%")';
  }
  pool.execute(query, [fileKey], (err, results) => {
    if (err) {
      console.error("Error fetching file from database:", err);
      return res.status(500).send("Error accessing file.");
    }

    if (results.length === 0) {
      return res.status(404).send("File not found.");
    }

    const { fileId, filename, path: filepath, username } = results[0];
    const id = isSlave ? fileId : results[0].id; // Use the appropriate ID (fileId for slave, id for master)
    const url = isSlave ? slaveServerURL : serverURL;

    // Determine content type for preview (if supported)
    const extname = path.extname(filename).toLowerCase();
    let contentType;
    let embedContent = "";

    if (
      extname === ".jpg" ||
      extname === ".jpeg" ||
      extname === ".png" ||
      extname === ".gif"
    ) {
      contentType = "image/" + extname.slice(1);
      embedContent = `<img src="/files/${id}/embed" alt="${filename}" />`; // Use fileId
    } else if (extname === ".mp4" || extname === ".webm") {
      contentType = "video/" + extname.slice(1);
      embedContent = `<video controls><source src="/files/${id}/embed" type="${contentType}"></video>`; // Use fileId
    } else if (
      extname === ".mp3" ||
      extname === ".wav" ||
      extname === ".aac" ||
      extname === ".ogg"
    ) {
      contentType = "audio/" + extname.slice(1);
      embedContent = `<audio controls><source src="/files/${id}/embed" type="${contentType}"></audio>`; // Use fileId
    } else {
      contentType = "application/octet-stream";
    }

    // Generate HTML for preview with download link
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta property="og:title" content="${filename} | ${serverName}" />
        <meta property="og:description" content="${serverName}" />
        <meta property="og:type" content="${contentType}" />
        <meta property="og:url" content="${url}/public/${id}" />
        <meta property="og:image" content="${url}/files/${id}/embed" />
        <meta property="og:video" content="${url}/files/${id}/embed" />
        <meta property="og:video:type" content="${contentType}" />
        <meta property="og:video:width" content="800" />
        <meta property="og:video:height" content="600" />
        
        <!-- Twitter Card for additional platform support -->
        <meta name="twitter:card" content="player" />
        <meta name="twitter:title" content="${filename} | ${serverName}" />
        <meta name="twitter:description" content="Uploaded by ${username}" />
        <meta name="twitter:player" content="${url}/files/${id}/embed" />
        <meta name="twitter:player:width" content="800" />
        <meta name="twitter:player:height" content="600" />
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                background-color: #181818;
                margin: 0;
                color: #fff;
                padding: 0 10px;
            }
            .frame {
                background-color: #fff;
                padding: 10px; /* Reduced padding */
                border-radius: 8px;
                box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
                max-width: 800px;
                margin-bottom: 20px;
                display: inline-block; /* Changed from flex to inline-block */
            }
            .frame-inner {
                display: flex;
                justify-content: center;
                align-items: center;
                width: 100%;
            }
            h1 {
                color: #f0f0f0;
                margin-bottom: 20px;
                text-align: center;
                font-size: 1.8rem;
                word-wrap: break-word;
            }
            img, video {
                width: auto;
                height: auto;
                max-width: 100%;
                max-height: 60vh; /* Further reduced max height */
                border-radius: 8px;
                object-fit: contain;
            }
            .user-info {
                color: #ccc;
                font-size: 0.9em;
                margin-top: 20px;
                text-align: center;
            }
            a {
                display: inline-block;
                padding: 12px 24px;
                background-color: #007bff;
                color: #fff;
                text-decoration: none;
                border-radius: 6px;
                margin-top: 20px;
                transition: background-color 0.3s ease, transform 0.2s ease;
            }
            a:hover {
                background-color: #0056b3;
                transform: translateY(-2px);
            }
            .copyright {
                color: #888;
                font-size: 0.75em;
                position: fixed;
                bottom: 10px;
                left: 50%;
                transform: translateX(-50%);
            }
            /* Mobile responsiveness */
            @media (max-width: 768px) {
                .frame {
                    width: 100%;
                    padding: 5px; /* Even less padding on mobile */
                }
                img, video {
                    max-height: 50vh; /* Further reduced on mobile */
                }
                h1 {
                    font-size: 1.5rem;
                }
                .user-info {
                    font-size: 0.8em;
                }
                a {
                    padding: 10px 20px;
                    font-size: 0.9em;
                }
            }
        </style>
    </head>
    <body>
        <h1>${filename}</h1>
        <div class="frame">
            <div class="frame-inner">
                ${embedContent ? embedContent : ""}
            </div>
        </div>
        <div class="user-info">Uploaded by: ${username}</div>
        <div style="text-align: center;">
            <a href="/files/${id}/download">Download</a>
            <a href="/files/${id}/embed">View</a>
        </div>
        <div class="copyright">&copy; 2024 ${copyrightHolder}</div>
    </body>
    </html>
    `;

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.send(html);
  });
});

// API endpoint for status
app.get("/status", (req, res) => {
  const html = `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Status</title>
    <style>
      body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
        margin: 0;
        background: linear-gradient(135deg, #f0f8ff, #d4f9e2);
        color: #333;
      }
      .status-container {
        text-align: center;
        padding: 20px 40px;
        background: #fff;
        border-radius: 10px;
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
      }
      .status {
        font-size: 3rem;
        font-weight: bold;
        color: #28a745;
        text-shadow: 1px 1px 4px rgba(0, 0, 0, 0.2);
      }
      .status:after {
        content: " ✅";
      }
    </style>
  </head>
  <body>
    <div class="status-container">
      <div class="status">UP</div>
    </div>
  </body>
  </html>
  `;

  res.setHeader("Content-Type", "text/html");
  res.send(html);
});

// Root endpoint redirecting to /status
app.get("/", (req, res) => {
  const html = `
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirecting...</title>
    <meta http-equiv="refresh" content="2;url=/status">
    <style>
      body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 100vh;
        margin: 0;
        background: linear-gradient(135deg, #ffefba, #ffffff);
        color: #333;
        text-align: center;
      }
      .redirect-message {
        font-size: 1.5rem;
        padding: 20px;
        background: #fff;
        border-radius: 10px;
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
      }
      .redirect-message span {
        color: #007bff;
        text-decoration: underline;
        cursor: pointer;
      }
    </style>
  </head>
  <body>
    <div class="redirect-message">
      Redirecting to <span onclick="window.location.href='/status'">/status</span>... <br />
      If you are not redirected automatically, <a href="/status">click here</a>.
    </div>
  </body>
  </html>
  `;

  res.setHeader("Content-Type", "text/html");
  res.send(html);
});

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
/*STATIC FILE UPLOADS*/

/// Create a new static folder
app.post("/static/folder/:name", authenticate, async (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  const folderName = req.params.name;
  const folderPath = path.join(STATIC_BASE_DIR, folderName);

  try {
    // Check if the folder exists
    try {
      await fs.promises.stat(folderPath); // Use fs.promises.stat()
      return res.status(409).send("Folder already exists.");
    } catch (statError) {
      // If stat throws an error, it means the folder doesn't exist
      if (statError.code !== "ENOENT") {
        throw statError; // Rethrow if it's not a "file not found" error
      }
    }

    // Create the folder
    await fs.promises.mkdir(folderPath, { recursive: true });
    res.status(201).send(`Folder '${folderName}' created successfully.`);
  } catch (err) {
    console.error("Error creating static folder:", err);
    res.status(500).send("Error creating folder.");
  }
});

// Delete a static folder
app.delete("/static/folder/:name", authenticate, async (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  const folderName = req.params.name;
  const folderPath = path.join(STATIC_BASE_DIR, folderName);

  try {
    // Check if the folder exists
    try {
      const stats = await fs.promises.stat(folderPath);
      if (!stats.isDirectory()) {
        return res.status(404).send("Folder not found.");
      }
    } catch (statError) {
      if (statError.code === "ENOENT") {
        return res.status(404).send("Folder not found.");
      }
      throw statError;
    }

    // Recursively remove the folder and its contents
    await fs.promises.rm(folderPath, { recursive: true, force: true });
    res.status(200).send(`Folder '${folderName}' deleted successfully.`);
  } catch (err) {
    console.error("Error deleting static folder:", err);
    res.status(500).send("Error deleting folder.");
  }
});

// Get folder contents
app.get("/static/folder", authenticate, async (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  try {
    // Use fs.promises for promise-based operations
    const folders = await fs.promises.readdir(STATIC_BASE_DIR);
    const folderDetails = await Promise.all(
      folders.map(async (folder) => {
        const folderPath = path.join(STATIC_BASE_DIR, folder);
        const stats = await fs.promises.stat(folderPath);
        if (!stats.isDirectory()) return null; // Skip if it's not a directory
        const files = await fs.promises.readdir(folderPath);
        return {
          name: folder,
          createdAt: stats.birthtime,
          fileCount: files.length,
        };
      })
    );

    // Filter out null values for non-directories
    res.json(folderDetails.filter((detail) => detail !== null));
  } catch (err) {
    console.error("Error listing static folders:", err);
    res.status(500).send("Error listing folders.");
  }
});

app.post(
  "/static/upload/:folder",
  authenticate,
  staticUpload.single("file"),
  async (req, res) => {
    if (isSlave) {
      return res.status(403).send("Please query the master server.");
    }

    if (!req.file) {
      return res.status(400).send("No file uploaded.");
    }

    const folderName = req.params.folder;
    const { filename, originalname, path: filePath, size } = req.file; // Added `size`

    try {
      // Insert file metadata into the database
      const query = `
      INSERT INTO static (folder, filename, originalname, path, size)
      VALUES (?, ?, ?, ?, ?)
    `;
      await pool.execute(query, [
        folderName,
        filename,
        originalname,
        filePath,
        size,
      ]);

      res.status(200).json({
        message: "File uploaded and metadata stored successfully.",
        filename,
        originalname,
        path: filePath,
        size, // Include size in the response
      });
    } catch (err) {
      console.error("Error storing file metadata in database:", err);
      res
        .status(500)
        .send("File uploaded, but failed to store metadata in database.");
    }
  }
);

app.get("/static/:folder/:fileId/embed", (req, res) => {
  const { folder, fileId } = req.params;
  // Convert fileId to integer
  const parsedFileId = parseInt(fileId);
  // Validate file ID
  if (isNaN(parsedFileId)) {
    return res.status(400).send("Invalid file ID.");
  }

  // Dynamic query based on potential slave configuration
  const query = isSlave
    ? "SELECT filename, path FROM static WHERE fileId = ? AND folder = ?"
    : "SELECT filename, path FROM static WHERE id = ? AND folder = ?";

  // Execute query with callback
  pool.query(query, [parsedFileId, folder], (err, results) => {
    // Check for database errors
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).send("Database error occurred.");
    }

    // Check if no results were found
    if (!results || results.length === 0) {
      return res.status(404).send("File not found.");
    }

    // Safely destructure first result
    const { filename, path: filepath } = results[0];

    // Additional validation
    if (!filename || !filepath) {
      return res.status(500).send("Invalid file information.");
    }

    // Determine content type
    const extname = path.extname(filename).toLowerCase();
    const contentTypeMap = {
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".png": "image/png",
      ".gif": "image/gif",
      ".mp4": "video/mp4",
      ".webm": "video/webm",
      ".ogg": "video/ogg",
    };
    const contentType = contentTypeMap[extname] || "application/octet-stream";

    // Safely resolve and read file
    let absolutePath;
    try {
      absolutePath = path.resolve(filepath);
    } catch (pathErr) {
      console.error("Path resolution error:", pathErr);
      return res.status(500).send("Error processing file path.");
    }

    // Create file stream
    let fileStream;
    try {
      fileStream = fs.createReadStream(absolutePath);
    } catch (readErr) {
      console.error("File read error:", readErr);
      return res.status(500).send("Error reading file.");
    }

    // Set up error handling
    fileStream.on("error", (streamErr) => {
      console.error("File stream error:", streamErr);
      if (!res.headersSent) {
        res.status(500).send("Error streaming file.");
      }
    });

    // Set headers and stream file
    res.setHeader("Content-Type", contentType);
    res.setHeader("Access-Control-Allow-Origin", "*");

    fileStream.pipe(res).on("error", (pipeErr) => {
      console.error("Pipe error:", pipeErr);
      if (!res.headersSent) {
        res.status(500).send("Error streaming file.");
      }
    });
  });
});

app.get("/static/:folder/:fileId/download", (req, res) => {
  const { folder, fileId } = req.params;
  const parsedFileId = parseInt(fileId);
  if (isNaN(parsedFileId)) {
    return res.status(400).send("Invalid file ID.");
  }

  const query = isSlave
    ? "SELECT originalname, path FROM static WHERE fileId = ? AND folder = ?"
    : "SELECT originalname, path FROM static WHERE id = ? AND folder = ?";

  // Execute query with callback
  pool.query(query, [parsedFileId, folder], (err, results) => {
    // Check for database errors
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).send("Database error occurred.");
    }

    // Check if no results were found
    if (!results || results.length === 0) {
      return res.status(404).send("File not found.");
    }

    // Safely destructure first result
    const { originalname, path: filepath } = results[0];

    // Additional validation
    if (!originalname || !filepath) {
      return res.status(500).send("Invalid file information.");
    }

    // Set headers for downloading the file with the original filename
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${originalname}"`
    );
    res.setHeader("Access-Control-Allow-Origin", "*");

    // Stream the file for download
    res.download(filepath, originalname, (err) => {
      if (err) {
        console.error("Error during file download:", err);
        res.status(500).send("Error downloading file.");
      }
    });
  });
});

app.get("/static/:folder/:fileid/public", (req, res) => {
  const { folder, fileid } = req.params;

  // Convert fileid to an integer
  const parsedFileId = parseInt(fileid, 10);
  if (isNaN(parsedFileId)) {
    return res.status(400).send("Invalid file ID.");
  }

  // Query the database for the file details by file ID
  const query = `
    SELECT originalname, path 
    FROM static 
    WHERE folder = ? AND id = ?`;

  pool.query(query, [folder, parsedFileId], (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).send("Database error occurred.");
    }

    if (!results || results.length === 0) {
      return res.status(404).send("File not found.");
    }

    const { originalname, path: filepath } = results[0];

    try {
      // Determine content type and embed content
      const extname = path.extname(originalname).toLowerCase();
      let contentType,
        embedContent = "";

      if ([".jpg", ".jpeg", ".png", ".gif"].includes(extname)) {
        contentType = `image/${extname.slice(1)}`;
        embedContent = `<img src="/static/${folder}/${fileid}/embed" alt="${originalname}" />`;
      } else if ([".mp4", ".webm"].includes(extname)) {
        contentType = `video/${extname.slice(1)}`;
        embedContent = `<video controls><source src="/static/${folder}/${fileid}/embed" type="${contentType}"></video>`;
      } else if ([".mp3", ".wav"].includes(extname)) {
        contentType = `audio/${extname.slice(1)}`;
        embedContent = `<audio controls><source src="/static/${folder}/${fileid}/embed" type="${contentType}"></audio>`;
      }

      // Generate HTML preview
      const html = `
      <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta property="og:title" content="${originalname} | ${serverName}" />
        <meta property="og:description" content="${serverName}" />
        <meta property="og:type" content="${contentType}" />
        <meta property="og:url" content="${serverURL}/static/${folder}/${fileid}/public" />
        <meta property="og:image" content="${serverURL}/static/${folder}/${fileid}/embed" />
        <meta property="og:video" content="${serverURL}/static/${folder}/${fileid}/embed" />
        <meta property="og:video:type" content="${contentType}" />
        <meta property="og:video:width" content="800" />
        <meta property="og:video:height" content="600" />
        
        <!-- Twitter Card for additional platform support -->
        <meta name="twitter:card" content="player" />
        <meta name="twitter:title" content="${originalname} | ${serverName}" />
        <meta name="twitter:description" content="Static File" />
        <meta name="twitter:player" content="${serverURL}/static/${folder}/${fileid}/embed" />
        <meta name="twitter:player:width" content="800" />
        <meta name="twitter:player:height" content="600" />
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
                background-color: #181818;
                margin: 0;
                color: #fff;
                padding: 0 10px;
            }
            .frame {
                background-color: #fff;
                padding: 10px; /* Reduced padding */
                border-radius: 8px;
                box-shadow: 0 8px 16px rgba(0, 0, 0, 0.1);
                max-width: 800px;
                margin-bottom: 20px;
                display: inline-block; /* Changed from flex to inline-block */
            }
            .frame-inner {
                display: flex;
                justify-content: center;
                align-items: center;
                width: 100%;
            }
            h1 {
                color: #f0f0f0;
                margin-bottom: 20px;
                text-align: center;
                font-size: 1.8rem;
                word-wrap: break-word;
            }
            img, video {
                width: auto;
                height: auto;
                max-width: 100%;
                max-height: 60vh; /* Further reduced max height */
                border-radius: 8px;
                object-fit: contain;
            }
            .user-info {
                color: #ccc;
                font-size: 0.9em;
                margin-top: 20px;
                text-align: center;
            }
            a {
                display: inline-block;
                padding: 12px 24px;
                background-color: #007bff;
                color: #fff;
                text-decoration: none;
                border-radius: 6px;
                margin-top: 20px;
                transition: background-color 0.3s ease, transform 0.2s ease;
            }
            a:hover {
                background-color: #0056b3;
                transform: translateY(-2px);
            }
            .copyright {
                color: #888;
                font-size: 0.75em;
                position: fixed;
                bottom: 10px;
                left: 50%;
                transform: translateX(-50%);
            }
            /* Mobile responsiveness */
            @media (max-width: 768px) {
                .frame {
                    width: 100%;
                    padding: 5px; /* Even less padding on mobile */
                }
                img, video {
                    max-height: 50vh; /* Further reduced on mobile */
                }
                h1 {
                    font-size: 1.5rem;
                }
                .user-info {
                    font-size: 0.8em;
                }
                a {
                    padding: 10px 20px;
                    font-size: 0.9em;
                }
            }
        </style>
    </head>
    <body>
        <h1>${originalname}</h1>
        <div class="frame">
            <div class="frame-inner">
                ${embedContent ? embedContent : ""}
            </div>
        </div>
        <div class="user-info">Static File</div>
        <div style="text-align: center;">
            <a href="/static/${folder}/${fileid}/download">Download</a>
            <a href="/static/${folder}/${fileid}/embed">View</a>
        </div>
        <div class="copyright">&copy; 2024 ${copyrightHolder}</div>
    </body>
    </html>`;

      res.send(html);
    } catch (err) {
      console.error("Error generating static file preview:", err);
      res.status(500).send("Error generating file preview.");
    }
  });
});

// Delete a static file
app.delete("/static/:folder/:fileid", authenticate, (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  const { folder, fileid } = req.params;

  // Convert fileid to an integer
  const parsedFileId = parseInt(fileid, 10);
  if (isNaN(parsedFileId)) {
    return res.status(400).send("Invalid file ID.");
  }

  // Query the database for the file details
  const query = `
    SELECT path 
    FROM static 
    WHERE folder = ? AND id = ?`;

  pool.query(query, [folder, parsedFileId], async (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).send("Database error occurred.");
    }

    if (!results || results.length === 0) {
      return res.status(404).send("File not found in the database.");
    }

    const { path: filepath } = results[0];

    try {
      // Use fs.promises to access and unlink the file
      await fs.promises.access(filepath);
      await fs.promises.unlink(filepath);

      // Delete the record from the database
      const deleteQuery = `DELETE FROM static WHERE id = ?`;
      pool.query(deleteQuery, [parsedFileId], (deleteErr) => {
        if (deleteErr) {
          console.error("Error deleting database record:", deleteErr);
          return res
            .status(500)
            .send("File deleted but database cleanup failed.");
        }
        res.status(200).send("File and database record deleted successfully.");
      });
    } catch (fsErr) {
      console.error("Error deleting static file:", fsErr);
      res.status(404).send("File not found on disk.");
    }
  });
});

app.get("/static/:folder/:fileid/info", authenticate, (req, res) => {
  const { folder, fileid } = req.params;

  const parsedFileId = parseInt(fileid, 10);
  if (isNaN(parsedFileId)) {
    return res.status(400).send("Invalid file ID.");
  }

  const query = `
    SELECT id, folder, filename, originalname, path, createdAt, size
    FROM static 
    WHERE folder = ? AND id = ?`;

  pool.query(query, [folder, parsedFileId], (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).send("Database error occurred.");
    }

    if (!results || results.length === 0) {
      return res.status(404).send("File not found in the database.");
    }

    res.status(200).json(results[0]);
  });
});

app.get("/static/:folder/contents", authenticate, (req, res) => {
  const { folder } = req.params;

  const query = `
    SELECT id, filename, originalname, path, createdAt 
    FROM static 
    WHERE folder = ?`;

  pool.query(query, [folder], (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).send("Database error occurred.");
    }

    if (!results || results.length === 0) {
      return res.status(404).send("No files found in the specified folder.");
    }

    res.status(200).json(results);
  });
});

app.put("/static/:folder/:fileid/rename", 
  authenticate, 
  body("newFilename")
    .notEmpty()
    .withMessage("New filename is required")
    .isLength({ min: 1, max: 100 })
    .withMessage("Filename must be between 1 and 100 characters")
    .matches(/^[a-zA-Z0-9_.-]+$/)
    .withMessage("Filename contains invalid characters"),
  (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  const { folder, fileid } = req.params;
  const { newFilename } = req.body;

  // Validate input
  if (!newFilename || typeof newFilename !== "string") {
    return res.status(400).send("Invalid or missing new file name.");
  }

  const parsedFileId = parseInt(fileid, 10);
  if (isNaN(parsedFileId)) {
    return res.status(400).send("Invalid file ID.");
  }

  const query = `
    SELECT path, filename 
    FROM static 
    WHERE folder = ? AND id = ?`;

  pool.query(query, [folder, parsedFileId], async (err, results) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).send("Database error occurred.");
    }

    if (!results || results.length === 0) {
      return res.status(404).send("File not found in the database.");
    }

    const { path: filepath, filename } = results[0];
    const newPath = path.join(path.dirname(filepath), newFilename);

    try {
      // Rename the file on disk
      await fs.promises.rename(filepath, newPath);

      // Update the database (update both filename and originalname)
      const updateQuery = `
        UPDATE static 
        SET path = ?, filename = ?, originalname = ? 
        WHERE id = ?`;
      pool.query(
        updateQuery,
        [newPath, newFilename, newFilename, parsedFileId],
        (updateErr) => {
          if (updateErr) {
            console.error("Error updating database record:", updateErr);
            return res
              .status(500)
              .send("File renamed but database update failed.");
          }
          res
            .status(200)
            .send("File renamed and database updated successfully.");
        }
      );
    } catch (fsErr) {
      console.error("Error renaming file:", fsErr);
      res.status(500).send("Error renaming file on disk.");
    }
  });
});

////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////
/*SERVER*/
// Serve static files (if needed)
app.use(express.static("public"));

app.listen(port, () => {
  console.log(
    serverName +
      " Version " +
      version +
      " by vncntwww listening on port " +
      port
  );
});
