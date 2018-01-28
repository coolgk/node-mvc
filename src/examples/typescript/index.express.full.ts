/**
 *
 */

import * as express from 'express';
import { formData } from '@coolgk/formdata';
import { config } from './config';
import { createClient } from 'redis';
import { parse } from 'cookie';

import { Router } from '../../router';

import { Session, COOKIE_NAME } from '@coolgk/session';

const app = express();

// ...some middlewares

app.use(async (request, response, next) => {

    const session = new Session({
        redisClient: createClient(config.redis),
        secret: config.secret,
        expiry: config.sessionMaxLife,
        request,
        response,
        cookie: {
            httpOnly: true,
            secure: config.secureCookie
        }
    });

    const router = new Router({
        rootDir: __dirname,
        url: request.originalUrl,
        method: request.method,
        formdata: formData(request, {dir: config.uploadDir}),
        session,
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
        console.error(result); // tslint:disable-line
        response.status(500).send('Internal Server Error');
    }

});

app.listen(3000);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error); // tslint:disable-line
});
