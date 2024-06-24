const mysql = require('mysql');
// const conn = mysql.createConnection({
//     host: process.env.DB_HOST,
//     user: process.env.DB_USERNAME,
//     password: process.env.DB_PASSWORD,
//     database: process.env.DB_NAME,
// });

console.log('host',process.env.DB_HOST)
var pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    "connectionLimit": 10
});

// console.log('Waiting for Mysql to Get Connected!~')

// conn.connect(function (err) {
//     if (err) throw err;
//     console.log("Connected!");
// });
module.exports = pool;
