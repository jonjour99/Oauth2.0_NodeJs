-- OAuth 2.0 서버 스키마

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    name            VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- OAuth 클라이언트(앱) 등록 테이블
CREATE TABLE IF NOT EXISTS clients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id           VARCHAR(64)  UNIQUE NOT NULL,
    -- public client(SPA, 모바일)는 NULL, confidential client는 해시된 secret
    client_secret_hash  VARCHAR(255),
    name                VARCHAR(100) NOT NULL,
    -- redirect_uri는 화이트리스트로 다중 등록 가능
    redirect_uris       TEXT[]       NOT NULL,
    -- 허용된 grant types: authorization_code, refresh_token 등
    grant_types         TEXT[]       NOT NULL DEFAULT ARRAY['authorization_code','refresh_token'],
    scopes              TEXT[]       NOT NULL DEFAULT ARRAY['openid','profile','email'],
    -- public client는 PKCE 필수
    is_confidential     BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- 인가 코드 테이블 (1회용, 짧은 수명)
CREATE TABLE IF NOT EXISTS authorization_codes (
    code                    VARCHAR(128) PRIMARY KEY,
    client_id               VARCHAR(64)  NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id                 UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri            TEXT         NOT NULL,
    scope                   TEXT         NOT NULL,
    -- PKCE
    code_challenge          VARCHAR(128) NOT NULL,
    code_challenge_method   VARCHAR(10)  NOT NULL,
    expires_at              TIMESTAMPTZ  NOT NULL,
    used                    BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Refresh token (해시 저장, 회전(rotation) 지원)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      VARCHAR(255) UNIQUE NOT NULL,
    client_id       VARCHAR(64)  NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope           TEXT         NOT NULL,
    expires_at      TIMESTAMPTZ  NOT NULL,
    revoked_at      TIMESTAMPTZ,
    -- 회전 추적 (재사용 탐지)
    replaced_by     UUID         REFERENCES refresh_tokens(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
