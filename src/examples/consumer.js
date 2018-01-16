'use strict';

const config = require('./config.js');
const logger = new (require('./core/loggers/logger.js'))();
const router = new (require('./lib/router.js'))();

function logInternalError (error) {
    logger.log(
        'consumer error handler: ' + (error ? error.message : ''),
        logger.LOG_LEVEL.CRITICAL,
        error ? error.stack : 'no trace, please check the request url'
    );
    // restarting process happens before the consumer can send a respose back, the message gets stuck in the queue
    // .then(() => {
        // restart worker. "write EPIPE" causes all requests fail
        // process.send({
            // type: 'restart'
        // });
    // });
    return JSON.stringify({response: [['status', 500], ['send', 'INTERNAL_ERROR']]});
}

let unhandledRejectionResolve;
process.on('unhandledRejection', (error) => unhandledRejectionResolve(logInternalError(error)));

new (require('./lib/messageQueue.js'))({
    url: config.amqp.url,
    sslPem: config.amqp.sslPem,
    sslCA: config.amqp.sslCA,
    sslPass: config.amqp.sslPass
}).consume(
    (rawMessage) => {
        try {
            const unhandledRejectionPromise = new Promise((resolve) => {
                unhandledRejectionResolve = resolve;
            });

            const message = JSON.parse(rawMessage.content.toString());

            const monitor = new (require('./lib/monitor.js'))({
                notifier: (usage) => {
                    logger.log('resource alert', logger.LOG_LEVEL.WARNING, null, usage);
                },
                threashold: {
                    responseTime: 3,
                    memory: 0.5,
                    cpu: 0.9,
                    load: 1
                }
            });

            logger.addDebugInfo(message.debugInfo);
            process.send({
                type: 'debugInfo',
                data: message.debugInfo
            });

            message.logger = logger;
                // return router.route(message).then(
                // (response) => {
                    // monitor.profile();
                    // return JSON.stringify(response);
                // }
            // ).catch(
                // (error) => logInternalError(error)
            // );

            return new Promise((resolve) => {
                // if unhandledRejection event triggers, router.route(message) will not get resolveed or rejected
                // unhandledRejectionPromise will be resolved and resolve the return promise
                router.route(message).then(
                    (response) => {
                        monitor.profile();
                        resolve(JSON.stringify(response));
                    }
                ).catch(
                    (error) => resolve(logInternalError(error))
                );
                // either above or below will resolve, not both
                unhandledRejectionPromise.then((error) => resolve(error));
            });
        } catch (error) {
            return Promise.resolve(logInternalError(error));
        }
    }
).catch(
    (error) => logInternalError(error)
);
