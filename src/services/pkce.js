'use strict';

const crypto = require('crypto');

/**
 * RFC 7636 PKCE 검증
 *
 * code_challenge_method:
 *   - "S256": BASE64URL(SHA256(code_verifier)) === code_challenge
 *   - "plain": code_verifier === code_challenge (권장하지 않음)
 *
 * code_verifier 형식 검증: 43~128자, [A-Z][a-z][0-9]-._~
 */
function base64UrlEncode(buf) {
    return buf
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function isValidVerifier(verifier) {
    return typeof verifier === 'string' && /^[A-Za-z0-9\-._~]{43,128}$/.test(verifier);
}

function verifyChallenge(verifier, challenge, method) {
    if (!isValidVerifier(verifier)) return false;
    if (method === 'S256') {
        const hash = crypto.createHash('sha256').update(verifier).digest();
        return base64UrlEncode(hash) === challenge;
    }
    if (method === 'plain') {
        // timing-safe 비교
        const a = Buffer.from(verifier);
        const b = Buffer.from(challenge);
        if (a.length !== b.length) return false;
        return crypto.timingSafeEqual(a, b);
    }
    return false;
}

module.exports = { verifyChallenge, isValidVerifier, base64UrlEncode };
