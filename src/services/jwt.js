'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * Access Token 발급 (JWT, HS256)
 * 운영에서는 RS256 + 키 페어 + JWKS 공개 권장.
 */
function signAccessToken({ sub, clientId, scope }) {
    return jwt.sign(
        {
            sub,
            client_id: clientId,
            scope,
            token_type: 'access_token',
        },
        config.jwt.secret,
        {
            algorithm: 'HS256',
            issuer: config.jwt.issuer,
            audience: clientId,
            expiresIn: config.jwt.accessTtl,
        }
    );
}

function verifyAccessToken(token) {
    return jwt.verify(token, config.jwt.secret, {
        algorithms: ['HS256'],
        issuer: config.jwt.issuer,
    });
}

module.exports = { signAccessToken, verifyAccessToken };
