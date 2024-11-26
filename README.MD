# Beacon CDN Server

This is a Node.js-based CDN server that provides file uploads, storage, and retrieval. It features user authentication, public file access with previews, and SSL encryption for secure communication.

## Features

* User authentication using JWT (JSON Web Tokens)
* File uploads with multer
* File storage using MariaDB and the server's file system
* API endpoints for file management (upload, list, delete, download)
* Public file access with previews for images and videos
* SSL encryption for HTTPS

## Technologies Used

* Node.js
* Express.js
* MariaDB
* JWT (jsonwebtoken)
* multer
* HTTPS

## Installation

1. Clone the repository: `git clone https://github.com/TheBeaconCrafter/cdn-server.git`
2. Install dependencies: `npm install`
3. Configure database connection:
    * Create a MariaDB database (e.g., `cdnserver`)
    * Create `users` and `files` tables (see SQL statements below)
4. Update settings in `configExample.js` and rename to `config.js`
5. Create a .env file that contains a random string for SYNC_SECRET="your_sync_secret" (see config.js)
6. Configure SSL encryption:
    * Obtain SSL certificates (private key, SSL certificate, intermediate certificate)
    * Drop them into the folder `ssl` (create if it doesn't exist)
7. Start the server with either `node index.js` or `./start.sh`

## Database Setup

**Create users table:**

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);
```
**Create your user account**

```sql
INSERT INTO users (username, password) VALUES ('your_username', 'your_password');
```

**Create files table:**

```sql
CREATE TABLE files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    path VARCHAR(255) NOT NULL,
    fileKey VARCHAR(255),
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

## Setup Second Server (not required)
This feature is not fully implemented and testet. Proceed with caution.
Known issues:
- Files deleted on the master are not yet deleted on the backup servers.

**If you want to use sync with two servers, set up a DB on the second server:**

```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);
```
**Create your user account**

```sql
INSERT INTO users (username, password) VALUES ('your_username', 'your_password');
```

**Create files table:**

```sql
CREATE TABLE files (
    id INT AUTO_INCREMENT PRIMARY KEY,
    userId INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    path VARCHAR(255) NOT NULL,
    fileKey VARCHAR(255),
    fileId INT UNIQUE,
    FOREIGN KEY (userId) REFERENCES users(id)
);
```

## API Endpoints

* **POST /upload:** Uploads a file (requires authentication via token received with /login)
* **GET /files/user/:userId:** Retrieves files for a specific user (requires authentication)
* **DELETE /files/:fileId:** Deletes a file (requires authentication)
* **GET /files/:fileId/download:** Downloads a file (public)
* **POST /login:** User login
* **GET /public/:fileId:** Public file access with preview and download

## Usage

1.  Upload files through the `/upload` endpoint after authenticating.
2.  Access and manage files using the provided API endpoints.
3.  Share files publicly using the `/public/:fileId` endpoint.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License (see LICENSE.MD for info).