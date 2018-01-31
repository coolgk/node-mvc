'use strict';
/**
 * an example controller using the @coolgk/mvc framework which decouples express from the main controller code
 */
const express = require('express');
const { Router } = require('@coolgk/mvc/router');

const app = express();

app.use(async (request, response, next) => {

    // configure router with minimum setup
    const router = new Router({
        rootDir: __dirname,
        url: request.originalUrl,
        method: request.method
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
