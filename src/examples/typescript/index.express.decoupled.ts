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
console.log(123123);
    const result = (await router.route());
console.log(result);
    result.json && response.json(result.json)
    || result.file && response.download(result.file.path, result.path.name)
    || result.status && response.status(result.code).send(result.status)
    || result.status && response.status(result.code).send(result.status);

});

app.listen(3000);
