'use strict';

const express = require('express');
const crypto = require('crypto');
const db = require('../db');
const config = require('../config');
const {
    findClient,
    isRedirectUriAllowed,
    clientSupportsGrant,
    filterAllowedScopes,
} = require('../services/clients');

const router = express.Router();

/**
 * GET /authorize
 *
 * 표준 파라미터:
 *   response_type=code
 *   client_id
 *   redirect_uri
 *   scope
 *   state                  (CSRF 방지용, 필수 권장)
 *   code_challenge         (PKCE)
 *   code_challenge_method  (S256 권장)
 *
 * 흐름:
 *   1. 클라이언트 + redirect_uri 검증 → 잘못되면 사용자에게 직접 에러 표시 (redirect 금지)
 *   2. 그 외 파라미터 오류는 redirect_uri로 error= 리다이렉트
 *   3. 로그인 안 됐으면 /login으로 보내고, 로그인 후 /authorize로 복귀
 *   4. (간소화) 동의 자동 승인 → 인가 코드 생성 후 redirect_uri로 리다이렉트
 */
router.get('/', async (req, res) => {
    const {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method,
    } = req.query;

    // 1) 클라이언트 검증
    if (!client_id || !redirect_uri) {
        return res.status(400).send('Invalid request: client_id and redirect_uri are required');
    }
    const client = await findClient(client_id);
    if (!client) {
        return res.status(400).send('Invalid client_id');
    }
    if (!isRedirectUriAllowed(client, redirect_uri)) {
        // 등록되지 않은 redirect_uri로는 절대 리다이렉트하지 않는다 (오픈 리다이렉트 방지).
        return res.status(400).send('Invalid redirect_uri');
    }

    const redirectError = (error, description) => {
        const url = new URL(redirect_uri);
        url.searchParams.set('error', error);
        if (description) url.searchParams.set('error_description', description);
        if (state) url.searchParams.set('state', state);
        return res.redirect(url.toString());
    };

    // 2) 파라미터 검증
    if (response_type !== 'code') {
        return redirectError('unsupported_response_type', 'response_type must be "code"');
    }
    if (!clientSupportsGrant(client, 'authorization_code')) {
        return redirectError('unauthorized_client');
    }
    // public client는 PKCE 필수
    if (!code_challenge) {
        return redirectError('invalid_request', 'code_challenge is required (PKCE)');
    }
    const method = code_challenge_method || 'plain';
    if (!['S256', 'plain'].includes(method)) {
        return redirectError('invalid_request', 'invalid code_challenge_method');
    }

    const grantedScope = filterAllowedScopes(client, scope);

    // 3) 로그인 확인
    if (!req.session.userId) {
        // 로그인 후 돌아올 수 있도록 원래 URL을 세션에 저장
        req.session.returnTo = req.originalUrl;
        return res.redirect('/login');
    }

    // 4) 인가 코드 생성 (단일 사용, 짧은 수명)
    const code = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + config.authCodeTtl * 1000);

    await db.query(
        `INSERT INTO authorization_codes
            (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
            code,
            client.client_id,
            req.session.userId,
            redirect_uri,
            grantedScope,
            code_challenge,
            method,
            expiresAt,
        ]
    );

    const url = new URL(redirect_uri);
    url.searchParams.set('code', code);
    if (state) url.searchParams.set('state', state);
    return res.redirect(url.toString());
});

module.exports = router;
