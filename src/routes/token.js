'use strict';

const express = require('express');
const db = require('../db');
const { authenticateClient, clientSupportsGrant } = require('../services/clients');
const { verifyChallenge } = require('../services/pkce');
const {
    findRefreshToken,
    issueTokenPair,
    revokeFamily,
} = require('../services/tokens');

const router = express.Router();

/**
 * POST /token
 *
 * 두 가지 grant_type을 처리한다:
 *   - authorization_code  : 인가 코드 + PKCE verifier → access/refresh token
 *   - refresh_token       : 회전(rotation) 적용. 재사용 탐지 시 패밀리 전체 무효화.
 *
 * 클라이언트 인증:
 *   - confidential: HTTP Basic 또는 body의 client_secret
 *   - public: client_id만, PKCE로 검증
 */

function tokenError(res, status, error, description) {
    return res.status(status).json({ error, error_description: description });
}

function getClientCredentials(req) {
    // RFC 6749 §2.3.1: HTTP Basic 우선
    const auth = req.headers.authorization;
    if (auth && auth.startsWith('Basic ')) {
        const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        if (idx > 0) {
            return {
                clientId: decodeURIComponent(decoded.slice(0, idx)),
                clientSecret: decodeURIComponent(decoded.slice(idx + 1)),
            };
        }
    }
    return {
        clientId: req.body.client_id,
        clientSecret: req.body.client_secret,
    };
}

router.post('/', async (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');

    const { grant_type } = req.body;
    if (!grant_type) {
        return tokenError(res, 400, 'invalid_request', 'grant_type is required');
    }

    const { clientId, clientSecret } = getClientCredentials(req);
    if (!clientId) {
        return tokenError(res, 401, 'invalid_client', 'client_id is required');
    }
    const client = await authenticateClient({ clientId, clientSecret });
    if (!client) {
        return tokenError(res, 401, 'invalid_client', 'client authentication failed');
    }
    if (!clientSupportsGrant(client, grant_type)) {
        return tokenError(res, 400, 'unauthorized_client', `grant_type ${grant_type} not allowed`);
    }

    if (grant_type === 'authorization_code') {
        return handleAuthCode(req, res, client);
    }
    if (grant_type === 'refresh_token') {
        return handleRefresh(req, res, client);
    }
    return tokenError(res, 400, 'unsupported_grant_type');
});

async function handleAuthCode(req, res, client) {
    const { code, redirect_uri, code_verifier } = req.body;
    if (!code || !redirect_uri) {
        return tokenError(res, 400, 'invalid_request', 'code and redirect_uri are required');
    }
    if (!code_verifier) {
        return tokenError(res, 400, 'invalid_request', 'code_verifier is required (PKCE)');
    }

    // 트랜잭션 + 단일 사용 보장
    const dbClient = await db.getClient();
    try {
        await dbClient.query('BEGIN');

        const { rows } = await dbClient.query(
            `SELECT * FROM authorization_codes WHERE code = $1 FOR UPDATE`,
            [code]
        );
        const auth = rows[0];

        if (!auth) {
            await dbClient.query('ROLLBACK');
            return tokenError(res, 400, 'invalid_grant', 'authorization code not found');
        }
        // 이미 사용된 코드를 재시도하면 → 도난 가능성. 발급된 토큰 패밀리 무효화.
        if (auth.used) {
            await dbClient.query('ROLLBACK');
            await revokeFamily(auth.user_id, auth.client_id);
            return tokenError(res, 400, 'invalid_grant', 'authorization code already used');
        }
        if (new Date(auth.expires_at) < new Date()) {
            await dbClient.query('ROLLBACK');
            return tokenError(res, 400, 'invalid_grant', 'authorization code expired');
        }
        if (auth.client_id !== client.client_id) {
            await dbClient.query('ROLLBACK');
            return tokenError(res, 400, 'invalid_grant', 'client mismatch');
        }
        if (auth.redirect_uri !== redirect_uri) {
            await dbClient.query('ROLLBACK');
            return tokenError(res, 400, 'invalid_grant', 'redirect_uri mismatch');
        }
        if (!verifyChallenge(code_verifier, auth.code_challenge, auth.code_challenge_method)) {
            await dbClient.query('ROLLBACK');
            return tokenError(res, 400, 'invalid_grant', 'PKCE verification failed');
        }

        // 코드 소비
        await dbClient.query(
            `UPDATE authorization_codes SET used = TRUE WHERE code = $1`,
            [code]
        );
        await dbClient.query('COMMIT');

        const tokenPair = await issueTokenPair({
            userId: auth.user_id,
            clientId: client.client_id,
            scope: auth.scope,
        });
        return res.json(tokenPair);
    } catch (err) {
        await dbClient.query('ROLLBACK').catch(() => {});
        console.error('token/auth_code error:', err);
        return tokenError(res, 500, 'server_error');
    } finally {
        dbClient.release();
    }
}

async function handleRefresh(req, res, client) {
    const { refresh_token, scope } = req.body;
    if (!refresh_token) {
        return tokenError(res, 400, 'invalid_request', 'refresh_token is required');
    }

    const stored = await findRefreshToken(refresh_token);
    if (!stored) {
        return tokenError(res, 400, 'invalid_grant', 'refresh token not found');
    }
    if (stored.client_id !== client.client_id) {
        return tokenError(res, 400, 'invalid_grant', 'client mismatch');
    }
    if (new Date(stored.expires_at) < new Date()) {
        return tokenError(res, 400, 'invalid_grant', 'refresh token expired');
    }
    // 재사용 탐지: 이미 회전되었거나 무효화된 토큰을 다시 사용하려는 시도 → 패밀리 전체 무효화
    if (stored.revoked_at || stored.replaced_by) {
        await revokeFamily(stored.user_id, stored.client_id);
        return tokenError(res, 400, 'invalid_grant', 'refresh token already used');
    }

    // 요청 scope는 기존 scope의 부분집합이어야 함
    let effectiveScope = stored.scope;
    if (scope) {
        const requested = scope.split(/\s+/).filter(Boolean);
        const original = new Set(stored.scope.split(/\s+/));
        if (!requested.every((s) => original.has(s))) {
            return tokenError(res, 400, 'invalid_scope');
        }
        effectiveScope = requested.join(' ');
    }

    // 회전: 기존 토큰을 revoke + replaced_by 설정
    const tokenPair = await issueTokenPair({
        userId: stored.user_id,
        clientId: client.client_id,
        scope: effectiveScope,
        oldRefreshId: stored.id,
    });
    return res.json(tokenPair);
}

module.exports = router;
