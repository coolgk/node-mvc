export interface IConfig {
    [index: string]: any;
}

export const config: IConfig = {
    secret: process.env.SECRET,
    host: 'localhost',
    port: 8000,
    uploadDir: __dirname + '/uploads',
    sessionMaxLife: 7200000,
    amqp: {
        url: process.env.AMQP_URL
    },
    redis: {
        host: process.env.REDIS_URL,
        password: process.env.REDIS_PASSWORD,
        port: process.env.REDIS_PORT
    },
    secureCookie: !!(process.env.SECURE_COOKIE || true)
};
