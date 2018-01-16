import { config } from './config';

import * as express from 'express';
import * as helmet from 'helmet';
import * as cors from 'cors';
import * as bodyParser from 'body-parser';
import * as cookieParser from 'cookie-parser';
import * as multer from 'multer';
// import * as Router from './router';

const app = express();

app.use((request, response, next) => {
    app.locals.response = response;
    next();
});

app.use(helmet()); // http://expressjs.com/en/advanced/best-practice-security.html
app.use(
    cors({
        origin: config.cors || '*',
        credentials: true
    })
);

// ============= SET UP POST VARIABLES
app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded

// ============= SETUP COOKIE
app.set('trust proxy', 1); // trust first proxy
app.use(cookieParser(config.secret));

// ============= SETUP ROUTER
app.use((request, response, next) => {

    (new Router({
        url: request.originalUrl,
        method: request.method,
        session: new Session({
            redisClient: require('redis').createClient(config.redis),
            secret: config.secret,
            expiry: config.sessionMaxLife,
            token: response.locals.cookie.get('accessToken') || (request.header('authorization') || '').replace(/^Bearer /, ''),
            ip: request.ip,
            cookie: {
                set: (name: string, value: string): void => {
                    response.cookie(name, value, {
                        httpOnly: true,
                        signed: true,
                        secure: config.secureCookie,
                        options.maxAge: config.sessionMaxLife || 0
                    });
                },
                clear (): void {
                    response.clearCookie(name);
                }
            }
        })
    })).route();

});

// ============= UNHANDLED REJECTIONS FROM PROMISE
process.on('unhandledRejection', (error) => {
    console.error(error);
    app.locals.response.headersSent || app.locals.response.sendStatus(500);
});

// ============= GLOBAL ERROR HANDLER (THIS DOES NOT CATCH UNHANDLED REJECTIONS)
// next is an unused variable but required for this callback
app.use((error, request, response, next) => { // eslint-disable-line no-unused-vars
    console.error(error);
    response.sendStatus(500);
});

// ============= START SERVER
const server = app.listen(config.port, config.host);
server.timeout = config.serverTimeout;
