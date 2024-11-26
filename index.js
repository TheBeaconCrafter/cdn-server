const express = require("express");
const multer = require("multer");
const path = require("path");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2"); // Import the mysql2 package
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
  syncSecret,
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

// API endpoint for syncing files
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
        // Optionally handle sync failure (e.g., mark for retry)
      }

      // Return a JSON response with fileId and fileKey
      res.status(200).json({
        fileId: fileId,
        fileKey: fileKey,
      });
    }
  );
});

// API endpoint to get files by a specific user
app.get("/files/user/:userId", authenticate, (req, res) => {
  if (isSlave) {
    return res.status(403).send("Please query the master server.");
  }

  const userId = req.params.userId;

  // Use a parameterized query
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
          // Consider logging this error and not blocking the response
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
      // Existing error checks...
  
      const { filename, path: filepath } = results[0];
      const absolutePath = path.resolve(filepath);
      
      // Determine content type
      const extname = path.extname(filename).toLowerCase();
      const contentTypeMap = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.mp4': 'video/mp4',
        '.webm': 'video/webm',
        '.ogg': 'video/ogg'
      };
  
      const contentType = contentTypeMap[extname] || 'application/octet-stream';
  
      // Create a read stream instead of using sendFile
      const fileStream = fs.createReadStream(absolutePath);
  
      fileStream.on('error', (streamErr) => {
        console.error("File stream error:", streamErr);
        if (!res.headersSent) {
          res.status(500).send("Error reading file.");
        }
      });
  
      res.setHeader('Content-Type', contentType);
      res.setHeader('Access-Control-Allow-Origin', '*');
      
      fileStream.pipe(res).on('error', (pipeErr) => {
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
      embedContent = `<img src="/files/${id}/download" alt="${filename}" />`; // Use fileId
    } else if (extname === ".mp4" || extname === ".webm") {
      contentType = "video/" + extname.slice(1);
      embedContent = `<video controls><source src="/files/${id}/download" type="${contentType}"></video>`; // Use fileId
    } else if (
      extname === ".mp3" ||
      extname === ".wav" ||
      extname === ".aac" ||
      extname === ".ogg"
    ) {
      contentType = "audio/" + extname.slice(1);
      embedContent = `<audio controls><source src="/files/${id}/download" type="${contentType}"></audio>`; // Use fileId
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
                ${embedContent ? embedContent : ''}
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

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', contentType);
    res.send(html);
  });
});

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
