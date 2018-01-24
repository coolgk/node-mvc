/**
 *
 */

import * as express from 'express';
import { formData } from '@coolgk/formdata';
import { config } from './config';
import { createClient } from 'redis';
import * as cookie from 'cookie';

import { Router } from '../../router';


import { Session, COOKIE_NAME } from '../../session';

const app = express();

// ...some middlewares

app.use(async (request, response, next) => {

    const cookies = cookie.parse(String(request.headers.cookie || ''));
    const accessToken = cookies[COOKIE_NAME] || String(request.headers.authorization || '').replace(/^Bearer /, '');

    const router = new Router({
        url: request.originalUrl,
        method: request.method,
        formdata: formData(request, {dir: config.uploadDir}),
        session: new Session({
            redisClient: createClient(config.redis),
            secret: config.secret,
            expiry: config.sessionMaxLife,
            token: accessToken,
            cookie: {
                set: (name: string, value: string): void => {
                    response.cookie(name, value, {
                        httpOnly: true,
                        secure: config.secureCookie,
                        maxAge: config.sessionMaxLife || 0
                    });
                },
                clear (): void {
                    response.clearCookie(name);
                }
            }
        }),
        config,
        ip: request.ip
    });

    const result = (await router.route());

    const responseSent = result.json && (response.json(result.json) || 1)
    || result.file && (response.download(result.file.path, result.file.name || '') || 1)
    || result.status && (response.status(result.code).send(result.status) || 1);

    // json, file and status are the only responses from this simple app
    // log error for anything else
    if (!responseSent) {
        // your custom error logger
        console.error(result);
        response.status(500).send('Internal Server Error');
    }

});

app.listen(3000);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error);
});
