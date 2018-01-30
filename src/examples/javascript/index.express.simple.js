'use strict';

/**
 * a simple example of using @coolgk/mvc framework for handling web requests
 */
const express = require('express');
const { Router } = require('@coolgk/mvc/router');

const app = express();

app.use(async (request, response, next) => {

    const router = new Router({
        rootDir: __dirname, // required param
        url: request.originalUrl, // required param
        method: request.method, // required param
        request, // you can pass anything into router, these variables will be available in controllers in this._options
        response, // pass express response to controller so we can send http response with this._options.response.send() etc.
        next // we don't use next() in this example, but if you pass it in, it will be available at this._options.next in your controller
    });

    // router.route() returns the return value of the controller method if the return value is not falsy
    // otherwise it returns an object from formatted by the "response" object (see the README file for @coolgk/mvc/response)
    // e.g. { code: 200, text: 'SUCCESS' }, { code: 200, json: {...} }, { code: 200, file: { name: ..., path: ... } } etc.
    const result = (await router.route());

    // for handling 404 / 403 returned from the router
    result && result.code && response.status(result.code).send(result.text);

});

app.listen(3000);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error); // tslint:disable-line
});
