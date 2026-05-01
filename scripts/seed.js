'use strict';

const bcrypt = require('bcrypt');
const crypto = require('crypto');
const db = require('../src/db');

/**
 * 데모용 사용자/클라이언트 시드
 *
 *   사용자: alice@example.com / password123
 *   클라이언트(public): client_id=demo-spa, redirect=http://localhost:8080/callback
 *   클라이언트(confidential): client_id=demo-server, secret=super-secret
 */
(async () => {
    const userPwHash = await bcrypt.hash('password123', 12);
    await db.query(
        `INSERT INTO users (email, password_hash, name)
         VALUES ($1, $2, $3)
         ON CONFLICT (email) DO NOTHING`,
        ['alice@example.com', userPwHash, 'Alice']
    );

    // public client (PKCE 필수, secret 없음)
    await db.query(
        `INSERT INTO clients (client_id, client_secret_hash, name, redirect_uris, grant_types, scopes, is_confidential)
         VALUES ($1, NULL, $2, $3, $4, $5, FALSE)
         ON CONFLICT (client_id) DO NOTHING`,
        [
            'demo-spa',
            'Demo SPA',
            ['http://localhost:8080/callback'],
            ['authorization_code', 'refresh_token'],
            ['openid', 'profile', 'email'],
        ]
    );

    // confidential client
    const secret = 'super-secret';
    const secretHash = await bcrypt.hash(secret, 12);
    await db.query(
        `INSERT INTO clients (client_id, client_secret_hash, name, redirect_uris, grant_types, scopes, is_confidential)
         VALUES ($1, $2, $3, $4, $5, $6, TRUE)
         ON CONFLICT (client_id) DO NOTHING`,
        [
            'demo-server',
            secretHash,
            'Demo Server App',
            ['http://localhost:8080/callback'],
            ['authorization_code', 'refresh_token'],
            ['openid', 'profile', 'email'],
        ]
    );

    console.log('Seed data inserted.');
    console.log('  user:     alice@example.com / password123');
    console.log('  public:   demo-spa (no secret)');
    console.log('  conf.:    demo-server / super-secret');

    // PKCE 데모용 verifier/challenge 출력
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto
        .createHash('sha256')
        .update(verifier)
        .digest('base64url');
    console.log('\n예시 PKCE 페어:');
    console.log('  code_verifier  :', verifier);
    console.log('  code_challenge :', challenge);

    await db.pool.end();
})().catch((err) => {
    console.error(err);
    process.exit(1);
});
