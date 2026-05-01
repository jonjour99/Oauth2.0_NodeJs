'use strict';

const { Pool } = require('pg');
const config = require('./config');

const pool = new Pool({ connectionString: config.db.connectionString });

pool.on('error', (err) => {
    console.error('Unexpected PG error:', err);
});

module.exports = {
    query: (text, params) => pool.query(text, params),
    getClient: () => pool.connect(),
    pool,
};
