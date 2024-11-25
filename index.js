const express = require('express');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2'); // Import the mysql2 package
const fs = require('fs');
const cors = require('cors');
const { body, validationResult } = require('express-validator');
const sanitizeFilename = require('sanitize-filename');

const app = express();
const upload = multer({ 
    dest: 'uploads/',
    limits: { fileSize: 1024 * 1024 * 1024 * 5 } // Limit file size to 5GB to make sure accidents don't happen
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
} = secrets;

app.use(express.json());
app.use(cors({ origin: corsOrigin }));

const pool = mysql.createPool(dbConfig);

// Test the database connection
pool.getConnection((err, connection) => {
    if (err) {
        console.error('Error connecting to database:', err);
    } else {
        console.log('Connected to MariaDB database');
        connection.release(); // Release the connection back to the pool
    }
});

const generateToken = (userId) => {
    // Customize the payload as needed (e.g., include user roles or permissions)
    const payload = { userId };
    return jwt.sign(payload, jwtSecret, { expiresIn: '1h' }); // Token expires in 1 hour
};

// Authentication middleware
const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.split(' ')[1]; // Get token from Authorization header

    if (!token) {
        return res.status(401).send('Authorization token missing.');
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.userId = decoded.userId; // Make userId available in the request object
        next();
    } catch (error) {
        res.status(401).send('Invalid token.');
    }
};

// API endpoint for file uploads (protected by authentication)
app.post('/upload', authenticate, upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const { originalname, path: filepath } = req.file;
    const userId = req.userId;

    // Extract the file key from the multer-generated filepath
    const fileKey = path.basename(filepath);

    // Sanitize the filename to remove problematic characters
    const sanitizedFilename = sanitizeFilename(originalname);
    
    if (!sanitizedFilename) {
        return res.status(400).send('Invalid filename.');
    }

    // Store file metadata in the database (including the file key)
    const query = 'INSERT INTO files (userId, filename, path, fileKey) VALUES (?, ?, ?, ?)';
    pool.execute(query, [userId, sanitizedFilename, filepath, fileKey], (err, results) => {
        if (err) {
            console.error('Error saving file metadata to database:', err);
            return res.status(500).send('Error uploading file.');
        }

        // Return a JSON response with fileId and fileKey
        res.status(200).json({ 
            fileId: results.insertId, 
            fileKey: fileKey 
        });
    });
});

// API endpoint to get files by a specific user
app.get('/files/user/:userId', authenticate, (req, res) => {
    const userId = req.params.userId;

    // Use a parameterized query
    const query = 'SELECT * FROM files WHERE userId = ?';

    pool.execute(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching files from database:', err);
            return res.status(500).send('Error fetching files.');
        }
        res.json(results);
    });
});

app.get('/files/:fileId', authenticate, (req, res) => {
    const fileId = parseInt(req.params.fileId);
    if (isNaN(fileId)) {
        return res.status(400).send('Invalid file ID.');
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
            console.error('Error fetching file details:', err);
            return res.status(500).send('Error getting file details.');
        }

        if (results.length === 0) {
            return res.status(404).send('File not found.');
        }

        const { path, user } = results[0];

        fs.stat(path, (err, stats) => {
            if (err) {
                console.error('Error getting file stats:', err);
                return res.status(500).send('Error getting file details.');
            }

            const key = path.split('/').pop(); // Extract key from the path

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
app.delete('/files/:fileId', authenticate, (req, res) => {
    const fileId = parseInt(req.params.fileId);
    if (isNaN(fileId)) {
        return res.status(400).send('Invalid file ID.');
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
            console.error('Error fetching file path from database:', err);
            return res.status(500).send('Error deleting file.');
        }

        if (results.length === 0) {
            return res.status(404).send('File not found.');
        }

        const fileUserId = results[0].userId;
        if (fileUserId !== req.userId) {
            return res.status(403).send('Forbidden. You do not have permission to delete this file: ' + fileUserId + ' ' + req.userId);
        }

        const filepath = results[0].path;

        // Delete the file from the database
        const deleteQuery = 'DELETE FROM files WHERE id = ?';
        pool.execute(deleteQuery, [fileId], (err, results) => {
            if (err) {
                console.error('Error deleting file from database:', err);
                return res.status(500).send('Error deleting file.');
            }

            // Delete the file from the file system
            fs.unlink(filepath, (err) => {
                if (err) {
                    console.error('Error deleting file from file system:', err);
                    // Consider logging this error and not blocking the response
                }
                res.send('File deleted successfully!');
            });
        });
    });
});

// API endpoint to download a file
app.get('/files/:fileId/download', (req, res) => {
    const fileId = parseInt(req.params.fileId);
    if (isNaN(fileId)) {
        return res.status(400).send('Invalid file ID.');
    }
    const query = 'SELECT filename, path FROM files WHERE id = ?';
    pool.execute(query, [fileId], (err, results) => {
        if (err) {
            console.error('Error fetching file from database:', err);
            return res.status(500).send('Error downloading file.');
        }

        if (results.length === 0) {
            return res.status(404).send('File not found.');
        }

        const { filename, path: filepath } = results[0];
        res.download(filepath, filename);
    });
});

// API endpoint to rename a file by ID (only in the database)
app.put('/files/:fileId/rename', 
    // Input validation using express-validator
    body('newFilename')
        .notEmpty().withMessage('New filename is required')
        .isLength({ min: 1, max: 100 }).withMessage('Filename must be between 1 and 100 characters')
        .matches(/^[a-zA-Z0-9_.-]+$/).withMessage('Filename contains invalid characters'),

    (req, res) => {
        const fileId = parseInt(req.params.fileId);
        if (isNaN(fileId)) {
            return res.status(400).send('Invalid file ID.');
        }

        // Check for validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array()   
 });
        }

        const
 { newFilename } = req.body; 

        const query = 'SELECT filename FROM files WHERE id = ?';
        pool.execute(query, [fileId], (err, results) => {
            if (err) {
                console.error('Error fetching file from database:', err);
                return res.status(500).send('Error renaming file.');
            }

            if (results.length === 0) {
                return res.status(404).send('File not found.');
            }

            const fileUserId = results[0].userId;
            if (fileUserId !== req.userId) {
                return res.status(403).send('Forbidden. You do not have permission to rename this file.');
            }

            // Update the file name in the database (without modifying the file on disk)
            const updateQuery = 'UPDATE files SET filename = ? WHERE id = ?';
            pool.execute(updateQuery, [newFilename, fileId], (updateErr) => {
                if (updateErr) {
                    console.error('Error updating filename in database:', updateErr);
                    return res.status(500).send('Error updating filename in database.');
                }

                res.status(200).send('File renamed successfully in the database.');
            });
        });
    }
);

app.get('/user/id/:username', authenticate, (req, res) => {
    const username = req.params.username;
    const query = 'SELECT id FROM users WHERE username = ?';

    pool.execute(query, [username], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Error retrieving user ID.');
        }

        if (results.length > 0) {
            const userId = results[0].id;
            res.send({ userId });
        } else {
            res.status(404).send('User not found.');
        }
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT id FROM users WHERE username = ? AND password = ?';

    pool.execute(query, [username, password], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Error during login: ' + err.message);
        }

        if (results.length > 0) {
            const userId = results[0].id;
            const token = generateToken(userId);
            res.send({ token });
        } else {
            res.status(401).send('Invalid credentials.');
        }
    });
});

// API endpoint for public file access with preview and download
app.get('/public/:fileKey', (req, res) => {
    const fileKey = req.params.fileKey; 
    const query = 'SELECT f.id, f.filename, f.path, u.username FROM files f JOIN users u ON f.userId = u.id WHERE f.path LIKE CONCAT("uploads/", ?, "%")';
    pool.execute(query, [fileKey], (err, results) =>  { 
        if (err) {
            console.error('Error fetching file from database:', err);
            return res.status(500).send('Error accessing file.');
        }

        if (results.length === 0) {
            return res.status(404).send('File not found.');
        }

        const { id: fileId, filename, path: filepath, username } = results[0]; // Get fileId

        // Determine content type for preview (if supported)
        const extname = path.extname(filename).toLowerCase();
        let contentType;
        let embedContent = '';

        if (extname === '.jpg' || extname === '.jpeg' || extname === '.png' || extname === '.gif') {
            contentType = 'image/' + extname.slice(1);
            embedContent = `<img src="/files/${fileId}/download" alt="${filename}" />`; // Use fileId
        } else if (extname === '.mp4' || extname === '.webm') {
            contentType = 'video/' + extname.slice(1);
            embedContent = `<video controls><source src="/files/${fileId}/download" type="${contentType}"></video>`; // Use fileId
        } else if (extname === '.mp3' || extname === '.wav' || extname === '.aac' || extname === '.ogg') {
            contentType = 'audio/' + extname.slice(1);
            embedContent = `<audio controls><source src="/files/${fileId}/download" type="${contentType}"></audio>`; // Use fileId
        } else {
            contentType = 'application/octet-stream'; 
        }        

        // Generate HTML for preview with download link
        const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta property="og:title" content="${filename} | ${serverName}" />
            <meta property="og:description" content="${serverName}" /> 
            <meta property="og:type" content="${contentType}" />
            <meta property="og:url" content="${serverURL}/public/${fileId}" />
            <meta property="og:image" content="${serverURL}/files/${fileId}/download" />
            <style> 
                body {
                    font-family: sans-serif;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                    background-color: #333; /* Dark background */
                    margin: 0;
                }

                .frame {
                    background-color: #fff;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
                    max-width: 800px; /* Max width of the frame */
                    max-height: 600px; /* Max height of the frame */
                    overflow: hidden;
                }

                h1 {
                    color: #eee;
                    margin-bottom: 10px;
                }

                img, video, audio {
                    max-width: 100%;
                    height: auto;
                    display: block; /* Prevents content from overflowing the frame */
                }

                .user-info {
                    color: #ccc;
                    font-size: 0.8em;
                    margin-top: 10px;
                }

                a {
                    display: inline-block;
                    padding: 10px 20px;
                    background-color: #007bff;
                    color: #fff;
                    text-decoration: none;
                    border-radius: 5px;
                    margin-top: 20px;
                    transition: background-color 0.3s ease;
                }

                a:hover {
                    background-color: #0069d9;
                }

                .copyright {
                    color: #777;
                    font-size: 0.8em;
                    position: fixed;
                    bottom: 10px;
                    left: 50%;
                    transform: translateX(-50%);
                }
            </style>
        </head>
        <body>
            <h1>${filename}</h1>
            <div class="frame">
                ${embedContent ? embedContent : ''} 
            </div>
            <div class="user-info">Uploaded by: ${username}</div>
            <br>
            <a href="/files/${fileId}/download">Download</a>
            <div class="copyright">&copy; 2024 ${copyrightHolder}</div>
        </body>
        </html>
        `;

        res.send(html);
    });
});

// Serve static files (if needed)
app.use(express.static('public'));

app.listen(port, () => {
    console.log(serverName + ' Version ' + version + ' by vncntwww listening on port ' + port);
});