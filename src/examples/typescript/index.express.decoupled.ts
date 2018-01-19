/**
 *
 */

import * as express from 'express';
import { Router } from '../../router';

const app = express();

app.use(async (request, response, next) => {

    const router = new Router({
        url: request.originalUrl,
        method: request.method
    });

    const result = (await router.route());

    const responseSent = result.json && response.json(result.json)
    || result.file && response.download(result.file.path, result.path.name)
    || result.status && response.status(result.code).send(result.status);

    // handler custom response result
    responseSent || response.json(result);

});

app.listen(3000);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error);
});
