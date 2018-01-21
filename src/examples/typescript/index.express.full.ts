/**
 *
 */

import * as express from 'express';
import { Router } from '../../router';
import { formdata } from '@coolgk/formdata';

const app = express();

// ...some middlewares

app.use(async (request, response, next) => {

    const router = new Router({
        url: request.originalUrl,
        method: request.method,
        formdata: formData(request)
    });

    const result = (await router.route());

    const responseSent = result.json && response.json(result.json)
    || result.file && response.download(result.file.path, result.path.name)
    || result.status && response.status(result.code).send(result.status);

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
