'use strict';

const bcrypt = require('bcrypt');
const db = require('../db');

async function findClient(clientId) {
    const { rows } = await db.query(
        `SELECT * FROM clients WHERE client_id = $1 LIMIT 1`,
        [clientId]
    );
    return rows[0] || null;
}

/**
 * confidential client는 client_secret을 검증한다.
 * public client(SPA, 모바일)는 secret이 없고 PKCE만으로 인증한다.
 */
async function authenticateClient({ clientId, clientSecret }) {
    const client = await findClient(clientId);
    if (!client) return null;

    if (client.is_confidential) {
        if (!clientSecret) return null;
        const ok = await bcrypt.compare(clientSecret, client.client_secret_hash);
        if (!ok) return null;
    }
    return client;
}

function isRedirectUriAllowed(client, redirectUri) {
    // RFC 6749: redirect_uri는 등록된 값과 정확히 일치해야 한다 (string-equality).
    return Array.isArray(client.redirect_uris) && client.redirect_uris.includes(redirectUri);
}

function clientSupportsGrant(client, grantType) {
    return Array.isArray(client.grant_types) && client.grant_types.includes(grantType);
}

function filterAllowedScopes(client, requestedScope) {
    if (!requestedScope) return (client.scopes || []).join(' ');
    const requested = requestedScope.split(/\s+/).filter(Boolean);
    const allowed = new Set(client.scopes || []);
    const granted = requested.filter((s) => allowed.has(s));
    return granted.join(' ');
}

module.exports = {
    findClient,
    authenticateClient,
    isRedirectUriAllowed,
    clientSupportsGrant,
    filterAllowedScopes,
};
