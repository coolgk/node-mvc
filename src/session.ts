import { Token, IRedisClient } from '@coolgk/token';
import { Jwt, IPayload } from '@coolgk/jwt';
// import { Request, Response } from 'express';
import { CookieSerializeOptions, serialize } from 'cookie';
import { ServerResponse } from 'http';

export interface IConfig {
    readonly redisClient: IRedisClient;
    readonly secret: string;
    readonly expiry: number;
    readonly token?: string;
    readonly cookie?: CookieSerializeOptions;
    readonly response?: ServerResponse;
}

export interface ISignature {
    [index: string]: any;
}

export const SESSION_NAME = 'session';
export const COOKIE_NAME = 'accessToken';

export class Session extends Token {

    private _jwt: Jwt;
    private _sessionToken: string;
    private _cookie: CookieSerializeOptions | undefined;
    private _response: ServerResponse | undefined;

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
        this._sessionToken = token;
        this._cookie = options.cookie;
        if (this._cookie) {
            this._cookie.maxAge = options.expiry;
        }
        this._response = options.response;
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
        return this._sessionToken;
    }

    /**
     * @return {promise<any>}
     */
    public async destroy (): Promise<any> {
        const destroyPromise = await super.destroy();
        if (this._cookie && this._response) {
            this._response.setHeader(
                'Set-Cookie',
                serialize(COOKIE_NAME, '', { ...this._cookie, maxAge: 0, expires: new Date()})
            );
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
    public async verifyAndRenew (): Promise<boolean> {
        if (await this.verify()) {
            await this.renew();
            return true;
        }
        return false;
    }

    public async renew (expiry?: number): Promise<any> {
        if (this._cookie && this._response) {
            this._response.setHeader(
                'Set-Cookie',
                serialize(COOKIE_NAME, this._sessionToken, this._cookie)
            );
        }
        return super.renew(expiry);
    }
}

export default Session;
