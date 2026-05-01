# OAuth 2.0 Authorization Server (Node.js)

Authorization Code + PKCE 흐름을 지원하는 OAuth 2.0 인가 서버 예제입니다.
RFC 6749(OAuth 2.0)와 RFC 7636(PKCE) 표준을 따라 구현했습니다.

## 구성

- 런타임: Node.js 18+ / Express 4
- 토큰: Access는 JWT(HS256), Refresh는 불투명(opaque) 토큰 + DB 회전
- 저장소: PostgreSQL 13+ (`gen_random_uuid()` 사용)
- 비밀번호/클라이언트 시크릿: bcrypt 해시
- 세션: express-session (사용자 로그인 상태 유지용)

## 폴더 구조

```
oauth-server/
├── package.json
├── .env.example
├── db/
│   └── schema.sql
├── scripts/
│   ├── init-db.js     # 스키마 적용
│   └── seed.js        # 데모 사용자/클라이언트 시드
└── src/
    ├── server.js      # Express 진입점
    ├── config.js
    ├── db.js
    ├── routes/
    │   ├── authorize.js
    │   ├── token.js
    │   ├── login.js
    │   └── userinfo.js
    └── services/
        ├── pkce.js
        ├── jwt.js
        ├── tokens.js
        └── clients.js
```

## 설치 & 실행

```bash
cd oauth-server
cp .env.example .env        # 비밀키들을 긴 무작위 문자열로 교체
npm install

# PostgreSQL DB/계정을 미리 만들어 둔 상태에서:
npm run init-db
npm run seed

npm run dev                 # nodemon으로 개발 서버 실행
```

DB는 다음과 같이 만들 수 있습니다:

```sql
CREATE USER oauth_user WITH PASSWORD 'oauth_pass';
CREATE DATABASE oauth_db OWNER oauth_user;
```

## 엔드포인트

| 메서드 | 경로         | 설명                                    |
|-------|-------------|----------------------------------------|
| GET   | `/authorize`| 인가 코드 발급(브라우저 리다이렉트)         |
| POST  | `/token`    | 토큰 발급 (`authorization_code`, `refresh_token`) |
| GET   | `/login`    | 사용자 로그인 폼                          |
| POST  | `/login`    | 로그인 처리 + 원래 페이지로 복귀             |
| GET   | `/userinfo` | 보호된 리소스 예시 (Bearer 토큰 필요)        |

## 흐름 요약 (Authorization Code + PKCE)

1. 클라이언트가 `code_verifier`를 생성 → SHA-256 해시 → base64url → `code_challenge`
2. 브라우저를 `/authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...&code_challenge_method=S256&state=...`로 보낸다.
3. 서버는 사용자 로그인 확인 후 인가 코드를 발급하고 `redirect_uri`로 리다이렉트한다.
4. 클라이언트가 `POST /token`에 `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier`를 전달한다.
5. 서버는 PKCE 검증(`SHA256(verifier) === challenge`) 후 access/refresh 토큰을 발급한다.
6. 보호된 리소스는 `Authorization: Bearer <access_token>`으로 호출한다.
7. access 만료 시 `grant_type=refresh_token`으로 새 토큰 페어를 받는다(이때 refresh 토큰은 회전되어 이전 토큰은 무효화).

## 보안 포인트

- `redirect_uri`는 등록된 값과 정확히 일치해야 함 (오픈 리다이렉트 방지)
- 인가 코드는 1회용 + 짧은 수명(기본 10분)
- 이미 사용된 코드를 재시도하면 해당 사용자/클라이언트의 refresh token 패밀리 전체를 무효화 (도난 탐지)
- Refresh token은 평문 저장하지 않고 SHA-256 해시만 보관
- Refresh token 회전: 사용 시마다 새 토큰을 발급하고 이전 토큰은 `revoked_at` + `replaced_by`로 추적
- Public client(SPA, 모바일)에는 PKCE 필수
- `Cache-Control: no-store` 응답 헤더로 토큰 캐싱 방지

## curl 예시

```bash
# 1) 인가 코드 받기 (브라우저에서 진행)
open "http://localhost:3000/authorize?response_type=code&client_id=demo-spa&redirect_uri=http://localhost:8080/callback&scope=openid%20profile%20email&state=xyz&code_challenge=<CHALLENGE>&code_challenge_method=S256"

# 2) 토큰 교환
curl -X POST http://localhost:3000/token \
  -d grant_type=authorization_code \
  -d code=<CODE> \
  -d redirect_uri=http://localhost:8080/callback \
  -d client_id=demo-spa \
  -d code_verifier=<VERIFIER>

# 3) 보호된 리소스 호출
curl http://localhost:3000/userinfo \
  -H "Authorization: Bearer <ACCESS_TOKEN>"

# 4) 토큰 갱신
curl -X POST http://localhost:3000/token \
  -d grant_type=refresh_token \
  -d refresh_token=<REFRESH_TOKEN> \
  -d client_id=demo-spa
```

## 운영 시 권장 사항

- JWT 알고리즘을 RS256/ES256으로 바꾸고 `/jwks.json` 공개 (키 회전 가능)
- HTTPS 강제 + `secure` 쿠키
- Rate limit (express-rate-limit) 적용
- 동의 화면(consent screen) 추가 — 현재는 자동 승인
- `id_token` 발급 + OpenID Connect Discovery(`/.well-known/openid-configuration`) 추가
- DB에 `iss`, `aud`, key id 등을 명시하고 토큰 폐기(revocation) 엔드포인트(RFC 7009) 추가
