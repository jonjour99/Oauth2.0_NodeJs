'use strict';

require('dotenv').config();

const required = (key) => {
    const v = process.env[key];
    if (!v) throw new Error(`Missing env var: ${key}`);
    return v;
};

module.exports = {
    port: parseInt(process.env.PORT || '3000', 10),
    env: process.env.NODE_ENV || 'development',

    sessionSecret: required('SESSION_SECRET'),

    jwt: {
        secret: required('JWT_SECRET'),
        issuer: process.env.JWT_ISSUER || 'http://localhost:3000',
        accessTtl: parseInt(process.env.JWT_ACCESS_TTL || '3600', 10),
        refreshTtl: parseInt(process.env.JWT_REFRESH_TTL || '1209600', 10),
    },

    db: {
        connectionString: required('DATABASE_URL'),
    },

    authCodeTtl: parseInt(process.env.AUTH_CODE_TTL || '600', 10),
};
