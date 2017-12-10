
export interface IConfig {
    secret: string;
    serverTimeout: number;
    host: string;
    port: number;
    sessionMaxLife: number;
    
    secureCookie: boolean;

        redis: {
            host: 'localhost',
            port: 6379
        },
        amqp: {
            url: 'amqp://localhost',
            sslPem: ''
        },
        smtp: {
            host: 'localhost'
        },
        db: {
            mongo: {
                url: '',
                sslPem: '',
                sslValidate: false,
                sslPass: '',
                sslCA: ''
            },
            periscope: {
                apiKey: '',
                periscopeUrl: '',
                baseApiUrl: ''
            },
            redshift: {
                user: '',
                database: '',
                password: '',
                port: 0,
                host: '',
                ssl: 'on'
            }
        },


    
    timezone: string;
    tmpDir: string;
    uploadDir: string;
};


'use strict';

module.exports = Object.assign(
    {
        secret: 'to-be-overwritten-by-local-config',
        serverTimeout: 600000, // 10 minutes to timeout server resopnse
        host: 'localhost',
        port: 3134,
        rootDir: __dirname,
        tmpDir: __dirname + '/.tmp',
        uploadDir: __dirname + '/uploads',
        timezone: 'Europe/London',
        sessionMaxLife: 7200000, // 2 hours 60 * 60 * 2 * 1000
        secureCookie: true,
        loginMaxAttempts: 5, // allow 5 failed login until applying loginLockoutTime
        loginLockoutTime: 600, // 10 minutes
        captcha: {
            enableWhenTried: 3,
            secret: 'to-be-overwritten-by-local-config'
        },
        aws: require('./config.aws.local.json'),
        adminModuleWhiteList: [],
        resetPasswordLinkExpiry: 3600000, // 1 hour
        loggers: [
            // __dirname + '/core/loggers/consolelog.js',
            // __dirname + '/core/loggers/slack.js',
            // __dirname + '/core/loggers/emailLogger.js',
            __dirname + '/core/loggers/dbLogger.js'
        ],
        db: {
            mongo: {
                url: '',
                sslPem: '',
                sslValidate: false,
                sslPass: '',
                sslCA: ''
            },
            periscope: {
                apiKey: '',
                periscopeUrl: '',
                baseApiUrl: ''
            },
            redshift: {
                user: '',
                database: '',
                password: '',
                port: 0,
                host: '',
                ssl: 'on'
            }
        },
        redis: {
            host: 'localhost',
            port: 6379
        },
        amqp: {
            url: 'amqp://localhost',
            sslPem: ''
        },
        smtp: {
            host: 'localhost'
        },
        email: {
            system: {
                name: '',
                email: ''
            },
            support: {
                name: '',
                email: ''
            }
        },
        slack: {
            webhooks: {
                portalnotice: ''
            }
        },
        client: {
            name: '',
            domains: [],
            requireCsrfToken: true
        }
        // , corsDomain: []
    },
    require('./config.local.js')
);
