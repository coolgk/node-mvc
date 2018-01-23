/**
 *
 */

import * as express from 'express';
import { Router } from '../../router';
import { formData } from '@coolgk/formdata';
import { config } from './config';

const app = express();

// ...some middlewares

app.use(async (request, response, next) => {

    const router = new Router({
        url: request.originalUrl,
        method: request.method,
        formdata: formData(request, {dir: config.uploadDir}),
        session: () => {},
        config
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
