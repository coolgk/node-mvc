'use strict';
/**
 * an extended example of using the @coolgk/mvc framework with session and form data handlers
 */
const express = require('express');
const { createClient } = require('redis');

const { Router } = require('@coolgk/mvc/router');

const { formData } = require('@coolgk/formdata');
const { Session } = require('@coolgk/session');

// import app configurations
const { config } = require('./config');

const app = express();

// ...some middleware

app.use(async (request, response, next) => {

    // initialise session
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
        rootDir: __dirname, // required
        url: request.originalUrl, // required
        method: request.method, // required
        // setup form data handler for 'application/json', 'application/x-www-form-urlencoded' and 'multipart/form-data'
        // see @coolgk/formdata https://www.npmjs.com/package/@coolgk/formdata
        formdata: formData(request, { dir: config.uploadDir }), // pass formdata in as a global dependency
        // pass session in as a global dependency
        session,
        config, // pass app config in as a global dependency
        ip: request.ip // pass ip address into router (controller methods)
    });

    // router.route() returns the return value of the controller method if the return value is not falsy
    // otherwise it returns an object formatted by the "response" object (see the README file for @coolgk/mvc/response)
    // e.g. { code: 200, text: 'SUCCESS' }, { code: 200, json: {...} }, { code: 200, file: { name: ..., path: ... } } etc.
    // this example uses the injected response object for setting up http responese in a standard format
    const result = (await router.route());

    // handle json, file or text responses
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
