/**
 * an example of using the @coolgk/mvc framework with rabbitMQ
 * a (catch all) message consumer for all tasks (routes)
 * single task consumers take precedence over this consumer
 * if a message's route cannot match single task consumers' routes, the message will be consumed by this consumer
 */
import { Amqp, IMessage } from '@coolgk/amqp';
import { Router } from '@coolgk/mvc/router';
// import app configurations
import { config } from './config';

// create an amqp (rabbitmq) instance
// see @coolgk/amqp https://www.npmjs.com/package/@coolgk/amqp
const amqp = new Amqp({
    url: config.amqp.url
});

// consume message and send (return) a response back to publisher
amqp.consume(
    async (publisherMessage: IMessage) => {
        console.log('consumer (default) received message', publisherMessage.message); // tslint:disable-line
        const router = new Router(publisherMessage.message);
        return await router.route();
    }
);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error); // tslint:disable-line
});
