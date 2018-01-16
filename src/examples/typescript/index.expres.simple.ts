import * as express from 'express';
import { Router } from './router';

const app = express();

app.use(async (request, response, next) => {
    const router = new Router({
        url: request.originalUrl,
        method: request.method,
        request,
        response,
        next
    });
    await router.route();
    next();
});

app.listen(3000);