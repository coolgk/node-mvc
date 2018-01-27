/**
 *
 */

import * as express from 'express';
import { Router } from '../../router';

const app = express();

app.use(async (request, response, next) => {

    const router = new Router({
        rootDir: __dirname,
        url: request.originalUrl,
        method: request.method
    });

    const result = (await router.route());

    const responseSent = result.json && (response.json(result.json) || 1)
    || result.file && (response.download(result.file.path, result.file.name || '') || 1)
    || result.status && (response.status(result.code).send(result.status) || 1);

    // handler custom response result
    responseSent || response.json(result);

});

app.listen(3000);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error); // tslint:disable-line
});
