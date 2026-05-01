'use strict';

const express = require('express');
const session = require('express-session');
const config = require('./config');

const authorizeRouter = require('./routes/authorize');
const tokenRouter = require('./routes/token');
const loginRouter = require('./routes/login');
const userinfoRouter = require('./routes/userinfo');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use(
    session({
        name: 'oauth.sid',
        secret: config.sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: 'lax',
            secure: config.env === 'production',
            maxAge: 1000 * 60 * 60, // 1시간
        },
    })
);

app.get('/', (req, res) => {
    res.json({
        name: 'OAuth 2.0 Authorization Server',
        endpoints: {
            authorize: '/authorize',
            token: '/token',
            login: '/login',
            userinfo: '/userinfo',
        },
    });
});

app.use('/authorize', authorizeRouter);
app.use('/token', tokenRouter);
app.use('/login', loginRouter);
app.use('/userinfo', userinfoRouter);

// 에러 핸들러
app.use((err, req, res, _next) => {
    console.error(err);
    res.status(500).json({ error: 'server_error' });
});

app.listen(config.port, () => {
    console.log(`OAuth server listening on http://localhost:${config.port}`);
});
