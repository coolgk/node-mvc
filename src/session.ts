import { Token, IRedisClient } from '@coolgk/token';
import { Jwt, IPayload } from '@coolgk/jwt';
import { Request } from 'express';

export interface ICookie {
    readonly set: (name: string, value: string) => void;
    readonly clear: (name: string) => void;
}

export interface IConfig {
    readonly redisClient: IRedisClient;
    readonly secret: string;
    readonly expiry: number;
    readonly token?: string;
    cookie?: ICookie;
}

export interface ISignature {
    [index: string]: any;
}

export const SESSION_NAME = 'session';
export const COOKIE_NAME = 'accessToken';

export class Session extends Token {

    private _jwt: Jwt;
    private _cookie: ICookie | undefined;
    private _sessionToken: string;

    /**
     * @param {object} options
     * @param {object} redisClient -
     * @param {string} secret -
     * @param {expiry} [expiry=3600] -
     * @param {string} [token] - a previously generated token string
     */
    public constructor (options: IConfig) {
        const token = options.token || '';
        super({
            token,
            redisClient: options.redisClient,
            expiry: options.expiry || 3600,
            prefix: SESSION_NAME
        });

        this._jwt = new Jwt({ secret: options.secret });
        this._cookie = options.cookie;
        this._sessionToken = token;
    }

    /**
     * @return {promise}
     */
    public init (signature: ISignature = {}): Promise<any> {
        return this.start(signature);
    }

    /**
     * @return {promise}
     */
    public rotate (signature: ISignature = {}): Promise<any> {
        return this.start(signature);
    }

    /**
     * @return {promise}
     */
    public async start (signature: ISignature = {}): Promise<any> {
        this._sessionToken = this._jwt.generate({ signature });
        this.setToken(this._sessionToken);
        await this.renew();
        if (this._cookie) {
            await this._cookie.set(COOKIE_NAME, this._sessionToken);
        }
        return this._sessionToken;
    }

    /**
     * @return {promise<any>}
     */
    public async destroy (): Promise<any> {
        const destroyPromise = await super.destroy();
        if (this._cookie) {
            return this._cookie.clear(COOKIE_NAME);
        }
        return destroyPromise;
    }

    /**
     * @return {promise<boolean>}
     */
    public async verify (signature: ISignature = {}): Promise<boolean> {
        const tokenData = this._jwt.verify(this._sessionToken);
        if (!tokenData
            || !tokenData.data
            || JSON.stringify((tokenData.data as IPayload).signature) !== JSON.stringify(signature)
        ) {
            return false;
        }
        return super.verify();
    }

    /**
     * @return {promise<boolean>}
     */
    public async verifyAndRenew () : Promise<boolean> {
        if (await this.verify()) {
            await this.renew();
            return true;
        }
        return false;
    }

}

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

export default Session;
