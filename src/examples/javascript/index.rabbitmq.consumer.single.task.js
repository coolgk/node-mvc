'use strict';
/**
 * an example of using the @coolgk/mvc framework with rabbitMQ
 * a message consumer for a single task (message from a specific route)
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

// consume message and send (return) a response back to the publisher
amqp.consume(
    async (publisherMessage) => {
        console.log('consumer (save) received message', publisherMessage.message); // eslint-disable-line
        const router = new Router(publisherMessage.message);
        return await router.route();
    },
    {
        exchangeName: 'direct',
        exchangeType: 'direct',
        fallbackExchange: 'defaultExchange',
        routes: 'example.decoupled.save' // only consume /example/decoupled/save request
    }
);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error); // eslint-disable-line
});
