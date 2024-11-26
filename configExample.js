//////////////////////////////////
//            CONFIG            //
//////////////////////////////////

// After you have filled in the following information, rename this file to config.js

// MariaDB Config
const dbConfig = {
    host: '127.0.0.1',  // If a connection error arrises for localhost, try 127.0.0.1
    user: 'cdnuser',
    password: 'password', // Replace with the actual password
    database: 'cdnserver',
};

// JWT Secret Key (Do not share!)
const jwtSecret = 'yourjwtsecret';

// Server Config
const version = '1.1.0';
const copyrightHolder = 'Example Person';
const serverName = 'Example CDN';
const serverURL = 'https://cdn.example.org'; // Example: https://cdn.example.org
const corsOrigin = '*'; // Example: https://cdn.example.org - Set to frontent URL
const port = 6635;

// Slave Server Config
/*
    If this server is a slave server, set isSlave to true
    and set the masterServerURL to the URL of the master server.
    The URL should be identifieable of the server so do not have two A/AAAA records pointing to the same server.
*/
const enableSyncing = false; // Set to true to enable syncing
const isSlave = false; // Set to true if this server is a slave server
const masterServerURL = 'https://cdn.example.org'; // Example: https://cdn.example.org
const slaveServerURL = 'https://cdn2.example.org'; // Example: https://cdn2.example.org
/*
    IMPORTANT:
    Please setup a .env file with the following content:

    SYNC_SECRET="your_sync_secret"

    If you don't set this up, syncing will not work!
    Choose a random string for the SYNC_SECRET and make sure it is the same on all servers.
*/

// Export all secrets - do not modify!
const secrets = {
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
};

module.exports = secrets;