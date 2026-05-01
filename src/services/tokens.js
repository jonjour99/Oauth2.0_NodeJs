'use strict';

const crypto = require('crypto');
const db = require('../db');
const config = require('../config');
const { signAccessToken } = require('./jwt');

/**
 * Refresh token은 DB에 SHA-256 해시로 저장한다.
 * 평문 토큰은 클라이언트에게만 1번 전달되고, 서버는 해시만 보관 → 유출 시에도 원본 복원 불가.
 * 또한 회전(rotation)을 통해 재사용 시 토큰 패밀리 전체를 무효화한다.
 */
function generateOpaqueToken(bytes = 48) {
    return crypto.randomBytes(bytes).toString('base64url');
}

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

async function createRefreshToken({ userId, clientId, scope, replacedById = null }) {
    const token = generateOpaqueToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + config.jwt.refreshTtl * 1000);

    const { rows } = await db.query(
        `INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id`,
        [tokenHash, clientId, userId, scope, expiresAt]
    );

    if (replacedById) {
        await db.query(
            `UPDATE refresh_tokens SET replaced_by = $1, revoked_at = now() WHERE id = $2`,
            [rows[0].id, replacedById]
        );
    }
    return token;
}

async function findRefreshToken(token) {
    const tokenHash = hashToken(token);
    const { rows } = await db.query(
        `SELECT * FROM refresh_tokens WHERE token_hash = $1 LIMIT 1`,
        [tokenHash]
    );
    return rows[0] || null;
}

/**
 * 모든 refresh_token chain을 끊는다 (재사용 탐지 시 호출).
 */
async function revokeFamily(userId, clientId) {
    await db.query(
        `UPDATE refresh_tokens
            SET revoked_at = now()
          WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL`,
        [userId, clientId]
    );
}

async function issueTokenPair({ userId, clientId, scope, oldRefreshId = null }) {
    const accessToken = signAccessToken({ sub: userId, clientId, scope });
    const refreshToken = await createRefreshToken({
        userId,
        clientId,
        scope,
        replacedById: oldRefreshId,
    });

    return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: config.jwt.accessTtl,
        refresh_token: refreshToken,
        scope,
    };
}

module.exports = {
    generateOpaqueToken,
    hashToken,
    createRefreshToken,
    findRefreshToken,
    revokeFamily,
    issueTokenPair,
};
