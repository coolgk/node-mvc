// import { Token, IRedisClient } from '@coolgk/token';
// import { Jwt } from '@coolgk/jwt';
// import {Request } from 'express';

// export interface ICookie {
    // readonly set: (name: string, value: string) => void;
    // readonly clear: (name: string) => void;
// }

// export interface IConfig {
    // readonly redisClient: IRedisClient;
    // readonly secret: string;
    // readonly expiry: number;
    // readonly token?: string;
    // cookie?: ICookie;
    // readonly ip?: string;
    // readonly jwt?: Jwt;
// }

// export const SESSION_NAME = 'session';
// export const TOKEN_NAME = 'accessToken';

// export class Session extends Token {

    // private _jwt: Jwt;
    // private _ip: string = '';
    // private _cookie: ICookie;

    // /**
     // * @param {object} options
     // * @param {object} redisClient -
     // * @param {string} secret -
     // * @param {expiry} [expiry=3600] -
     // * @param {string} [token] - a previously generated token string
     // * @param {string} [ip] -
     // */
    // public constructor (options: IConfig) {
        // super({
            // token: options.token,
            // redisClient: options.redisClient,
            // expiry: options.expiry || 3600,
            // prefix: SESSION_NAME
        // });

        // this._jwt = new (options.jwt || Jwt)({secret: options.secret});
        // this._ip = options.ip;
        // this._cookie = options.cookie;
    // }

    // /**
     // * @return {promise}
     // */
    // public async start (data): Promise<any> {
        // this._token = jwt.generate({...data, ip: this._ip});
        // const renewPromise = await this.renew();
        // if (this._cookie) {
            // return this._cookie.set(TOKEN_NAME, this.token);
        // }
        // return this._token;
    // }

    // /**
     // * @return {promise<any>}
     // */
    // public async destroy (): Promise<any> {
        // const destroyPromise = await super.destroy();
        // if (this._cookie) {
            // return this._cookie.clear(TOKEN_NAME);
        // }
        // return this._token;
    // }

    // /**
     // * @return {promise<boolean>}
     // */
    // public async verify (): Promise<boolean> {
        // const tokenData = this._jwt.verify(this._token);
        // if (this._ip && this._ip !== (tokenData.data || {}).ip) {
            // return false;
        // }
        // return super.verify();
    // }

    // /**
     // * @return {promise<boolean>}
     // */
    // public async verifyAndRenew () : Promise<boolean> {
        // if (await this.verify()) {
            // await this.renew();
            // return true;
        // }
        // return false;
    // }

// }

// export interface IExpressConfig extends IConfig {
    // httpOnly?: boolean;
    // signed?: boolean;
    // secure?: boolean;
    // requestFieldName?: string;
// }

// export const express = (options: IExpressConfig) => {
    // return (request, response, next: () => void) => {
        // if (!options.cookie) {
            // options.cookie = {
                // set: (name: string, value: string): void => {
                    // response.cookie(name, value, {
                        // httpOnly: options.httpOnly,
                        // signed: options.signed,
                        // secure: options.secure,
                        // maxAge: options.expiry || 0
                    // });
                // },
                // clear (): void {
                    // response.clearCookie(name);
                // }
            // };
        // }
        // request[options.requestFieldName || 'session'] = new Session(options);
        // next();
    // }
// }

// export default Session;
