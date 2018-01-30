'use strict';

exports.config = {
    secret: process.env.SECRET || '',
    host: 'localhost',
    port: 8000,
    uploadDir: __dirname + '/uploads',
    sessionMaxLife: 7200,
    amqp: {
        url: process.env.AMQP_URL
    },
    redis: {
        host: process.env.REDIS_HOST,
        password: process.env.REDIS_PASSWORD,
        port: Number(process.env.REDIS_PORT)
    },
    secureCookie: process.env.SECURE_COOKIE !== '0'
};
