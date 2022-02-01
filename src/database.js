const mysql = require('mysql');
const { promisify } = require('util');
const { database } = require('./keys');

const pool = mysql.createPool(database);
pool.getConnection((err, connection) => {
    if(err){
        if(err.code == 'PROTOCOL_CONNECTION_LOST'){
            console.log('DATABASE CONNECTION WAS CLOSED');
        }
        if(err.code == 'ER_CON:COUNT_ERROR'){
            console.log('DATABASE HAS TO MANY CONNECTIONS');
        }
        if(err.code == 'ENCOONREFUSED'){
            console.log('DATABASE CONNECTION WAS REFUSED');
        }
    }

    if(connection) connection.release();
    console.log('DB is Connected');
});

pool.query = promisify(pool.query);

module.exports = pool;