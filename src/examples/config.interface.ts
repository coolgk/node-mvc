export interface IConfig {
    secret?: string;
    serverTimeout?: number;
    host?: string;
    port?: number;
    sessionMaxLife?: number;
    cors?: string[];
    secureCookie?: boolean;
    timezone?: string;
    uploadFolder?: string;
    tmpFolder?: string;
    redis?: {
        host: string;
        port: number;
        password?: string;
    };
};
