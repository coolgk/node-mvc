/**
 * an extended example of the @coolgk/mvc framework with session and form data handlers
 */

import * as express from 'express';
import { createClient } from 'redis';

import { Router } from '@coolgk/mvc/router';

import { formData } from '@coolgk/formdata';
import { Session } from '@coolgk/session';

// import app configurations
import { config } from './config';

const app = express();

// ...some middleware

app.use(async (request, response, next) => {

    // initilaise session
    // see @coolgk/session https://www.npmjs.com/package/@coolgk/session
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

    // setup router
    const router = new Router({
        rootDir: __dirname, // required param
        url: request.originalUrl, // required param
        method: request.method, // required param
        // setup form data handler for 'application/json', 'application/x-www-form-urlencoded' and 'multipart/form-data'
        // see @coolgk/formdata https://www.npmjs.com/package/@coolgk/formdata
        formdata: formData(request, { dir: config.uploadDir }), // pass formdata in as global a dependency
        // pass session in as global a dependency
        session,
        config, // pass app config in as global a dependency
        ip: request.ip // pass ip address into router (controller methods)
    });

    // this example uses the injected response object for setting up http responese in a standard format
    const result = (await router.route());

    // handle session, file or text responses
    const responseSent = result.json && (response.json(result.json) || 1)
    || result.file && (response.download(result.file.path, result.file.name || '') || 1)
    || result.code && (response.status(result.code).send(result.text) || 1);

    // json, file and text are the only valid responses from this simple app
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