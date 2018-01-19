import * as express from 'express';
import { Router } from '../../router';

const app = express();

app.use(async (request, response, next) => {

    const router = new Router({
        url: request.originalUrl,
        method: request.method,
        request,
        response,
        next
    });

    const result = (await router.route());

    if (result && result.code) {
        response.status(result.code).send(result.status);
    }

});

app.listen(3000);
