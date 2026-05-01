'use strict';

const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db');

const router = express.Router();

const FORM = (errorMsg = '') => `
<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><title>로그인</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 360px; margin: 80px auto; }
  input { display:block; width:100%; padding:8px; margin:6px 0 14px; box-sizing:border-box; }
  button { padding:10px 16px; }
  .err { color: #c00; }
</style></head><body>
<h2>OAuth 서버 로그인</h2>
${errorMsg ? `<p class="err">${errorMsg}</p>` : ''}
<form method="POST" action="/login">
  <label>이메일<input name="email" type="email" required autofocus></label>
  <label>비밀번호<input name="password" type="password" required></label>
  <button type="submit">로그인</button>
</form>
</body></html>`;

router.get('/', (req, res) => {
    res.send(FORM());
});

router.post('/', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).send(FORM('이메일과 비밀번호를 입력하세요'));
    }

    const { rows } = await db.query(
        `SELECT id, password_hash FROM users WHERE email = $1 LIMIT 1`,
        [email]
    );
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.status(401).send(FORM('이메일 또는 비밀번호가 올바르지 않습니다'));
    }

    req.session.userId = user.id;
    const returnTo = req.session.returnTo || '/';
    delete req.session.returnTo;
    res.redirect(returnTo);
});

module.exports = router;
