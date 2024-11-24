const express = require('express');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2'); // Import the mysql2 package
const fs = require('fs');
const cors = require('cors');

const app = express();
const upload = multer({ dest: 'uploads/' }); // Customize the destination folder

const secrets = require("./config.js"); 

const {
    dbConfig,
    jwtSecret,
    version,
    serverName,
    serverURL,
    port,
    copyrightHolder,
} = secrets;

app.use(express.json());
app.use(cors({ origin: '*' })); //TODO: Change to specific origin

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

    // Store file metadata in the database (including the file key)
    const query = 'INSERT INTO files (userId, filename, path, fileKey) VALUES (?, ?, ?, ?)';
    pool.execute(query, [userId, originalname, filepath, fileKey], (err, results) => {
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
    const userId = parseInt(req.params.userId);
    const query = 'SELECT * FROM files WHERE userId = ?';
    pool.execute(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching files from database:', err);
            return res.status(500).send('Error fetching files.');
        }
        res.json(results);
    });
});

// API endpoint to delete a specific file
app.delete('/files/:fileId', authenticate, (req, res) => {
    const fileId = parseInt(req.params.fileId);

    // Fetch the file path from the database
    const selectQuery = 'SELECT path FROM files WHERE id = ?';
    pool.execute(selectQuery, [fileId], (err, results) => {
        if (err) {
            console.error('Error fetching file path from database:', err);
            return res.status(500).send('Error deleting file.');
        }

        if (results.length === 0) {
            return res.status(404).send('File not found.');
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

// API endpoint to get files by a specific user
app.get('/files/user/:userId', authenticate, (req, res) => {
    const userId = parseInt(req.params.userId);
    const userFiles = files.filter((file) => file.userId === userId);
    res.json(userFiles);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT id FROM users WHERE username = ? AND password = ?';

    pool.execute(query, [username, password], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Error during login.');
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
    const query = 'SELECT f.id, f.filename, f.path, u.username FROM files f JOIN users u ON f.userId = u.id WHERE f.path LIKE ?'; // Select f.id
    pool.execute(query, [`uploads/${fileKey}%`], (err, results) => { 
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

                img, video {
                    max-width: 100%;
                    height: auto;
                    display: block; /* Prevents image from overflowing the frame */
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
                ${embedContent} 
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