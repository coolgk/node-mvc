/**
 * a simple example of using express
 */

import * as express from 'express';
import { Amqp, IResponseMessage } from '@coolgk/amqp';

import { Router } from '../../router';

const app = express();

app.use(async (request, response, next) => {

    const amqp = new Amqp({
        url: process.env.AMQP_URL || ''
    });

    const routerConfig = {
        url: request.originalUrl,
        method: request.method
    };

    const router = new Router(routerConfig);
    const { module, controller, action } = router.getModuleControllerAction();

    const responseHandler = (consumerResponse: IResponseMessage) => {
        console.log('consumer replied: ', consumerResponse.responseMessage);
        const result = consumerResponse.responseMessage;

        const responseSent = result.json && response.json(result.json)
        || result.file && response.download(result.file.path, result.path.name)
        || result.status && response.status(result.code).send(result.status);

        // handler custom response result
        responseSent || response.json(result);
    };

    amqp.publish(
        routerConfig,
        responseHandler,
        {
            route: `${module}.${controller}.${action}`
        }
    );

});

app.listen(3000);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error);
});
