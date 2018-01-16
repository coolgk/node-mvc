/*
import { IConfig } from './config.interface';
import { config as localConfig } from './config.local';

export const config: IConfig = Object.assign(
    {
        host: null,
        port: 3000,
        sessionMaxLife: 7200000, // 2 hours 60 * 60 * 2 * 1000
        secret: 'to-be-overwritten-by-local-config',
        serverTimeout: 600000, // 10 minutes to timeout server resopnse
        cors: ['*'],
        timezone: 'Europe/London',
        uploadFolder: __dirname + '/uploads',
        tmpFolder: __dirname + '/tmp',
        secureCookie: true,
        redis: {
            host: 'localhost',
            port: 6379
        }
    },
    localConfig
);
*/