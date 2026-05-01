'use strict';

const express = require('express');
const db = require('../db');
const { verifyAccessToken } = require('../services/jwt');

const router = express.Router();

/**
 * GET /userinfo - 보호된 리소스 예시
 *
 * Bearer 토큰을 검증해서 토큰 소유자 정보를 반환한다.
 * RFC 6750: WWW-Authenticate: Bearer realm="..."
 */
router.get('/', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
        res.set('WWW-Authenticate', 'Bearer realm="oauth-server"');
        return res.status(401).json({ error: 'invalid_token' });
    }
    const token = auth.slice(7);

    let payload;
    try {
        payload = verifyAccessToken(token);
    } catch (err) {
        res.set(
            'WWW-Authenticate',
            `Bearer error="invalid_token", error_description="${err.message}"`
        );
        return res.status(401).json({ error: 'invalid_token' });
    }

    const { rows } = await db.query(
        `SELECT id, email, name FROM users WHERE id = $1 LIMIT 1`,
        [payload.sub]
    );
    if (!rows[0]) {
        return res.status(404).json({ error: 'user_not_found' });
    }
    return res.json({
        sub: rows[0].id,
        email: rows[0].email,
        name: rows[0].name,
        scope: payload.scope,
    });
});

module.exports = router;
