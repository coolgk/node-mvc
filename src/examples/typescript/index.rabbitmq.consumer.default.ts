/**
 * a simple example of using express
 */

import { Amqp, IMessage } from '@coolgk/amqp';
import { Router } from '../../router';

const amqp = new Amqp({
    url: process.env.AMQP_URL || ''
});

// consume message and return (send) a response back to publisher
amqp.consume(
    async (publisherMessage: IMessage) => {
        console.log('consumer (default) received message', publisherMessage.message);
        const router = new Router(publisherMessage.message);
        return await router.route();
    }
);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error);
});
