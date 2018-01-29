/**
 * a simple example of using express
 */

import * as express from 'express';
import { Router } from '../../router';

const app = express();

app.use(async (request, response, next) => {

    const router = new Router({
        rootDir: __dirname,
        url: request.originalUrl,
        method: request.method,
        request,
        response,
        next
    });

    const result = (await router.route());

    // for handling 404 / 403 returned from the router
    result && result.status && response.status(result.code).send(result.status);

});

app.listen(3000);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error); // tslint:disable-line
});
