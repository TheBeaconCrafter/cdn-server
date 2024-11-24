//////////////////////////////////
//            CONFIG            //
//////////////////////////////////

// After you have filled in the following information, rename this file to config.js

// MariaDB Config
const dbConfig = {
    host: 'localhost',
    user: 'cdnuser',
    password: 'password', // Replace with the actual password
    database: 'cdnserver',
};

// JWT Secret Key (Do not share!)
const jwtSecret = 'yourjwtsecret';

// Server Config
const version = '1.0.0';
const copyrightHolder = 'Example Person';
const serverName = 'Example CDN';
const serverURL = 'https://cdn.example.org'; // Example: https://cdn.example.org
const port = 6635;

// Export all secrets - do not modify!
const secrets = {
    dbConfig,
    jwtSecret,
    version,
    serverName,
    serverURL,
    port,
    copyrightHolder,
};

module.exports = secrets;