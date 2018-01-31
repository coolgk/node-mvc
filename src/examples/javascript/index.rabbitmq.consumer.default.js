'use strict';
/**
 * an example of using the @coolgk/mvc framework with rabbitMQ
 * a (catch all) message consumer for all tasks (routes)
 * single task consumers take precedence over this consumer
 * if a message's route cannot match single task consumers' routes, the message will be consumed by this consumer
 */
const { Amqp } = require('@coolgk/amqp');
const { Router } = require('@coolgk/mvc/router');
// import app configurations
const { config } = require('./config');

// create an amqp (rabbitmq) instance
// see @coolgk/amqp https://www.npmjs.com/package/@coolgk/amqp
const amqp = new Amqp({
    url: config.amqp.url
});

// consume message and send (return) a response back to publisher
amqp.consume(
    async (publisherMessage) => {
        console.log('consumer (default) received message', publisherMessage.message); // eslint-disable-line
        const router = new Router(publisherMessage.message);
        return await router.route();
    }
);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error); // eslint-disable-line
});
