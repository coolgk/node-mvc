import { ICacheClient } from './cache';
import { Token } from './token';
import { Jwt } from './jwt';

export interface ICookie {
    readonly set: (name: string, value: string) => void;
    readonly clear: (name: string) => void;
}

export interface IConfig {
    readonly redisClient: ICacheClient;
    readonly secret: string;
    readonly expiry: number;
    readonly token?: string;
    readonly cookie?: ICookie;
    readonly ip?: string;
    readonly jwt?: Jwt;
}

export const SESSION_NAME = 'session';
export const TOKEN_NAME = 'accessToken';

export default class Session extends Token {

    private _jwt: Jwt;
    private _ip: string = '';
    private _cookie: ICookie;

    public constructor (options: IConfig) {
        super({
            token: options.token,
            redisClient: options.redisClient,
            expiry: options.expiry || 3600,
            prefix: SESSION_NAME
        });

        this._jwt = new (options.jwt || Jwt)({secret: options.secret});
        this._ip = options.ip;
        this._cookie = options.cookie;
    }

    /**
     * @return {promise}
     */
    public async start (data): Promise<any> {
        this._token = jwt.generate({...data, ip: this._ip});
        const renewPromise = await this.renew();
        if (this._cookie) {
            return this._cookie.set(TOKEN_NAME, this.token);
        }
        return renewPromise;
    }

    /**
     * @return {promise}
     */
    public async destroy (): Promise<any> {
        const destroyPromise = await super.destroy();
        if (this._cookie) {
            return this._cookie.clear(TOKEN_NAME);
        }
        return destroyPromise;
    }

    /**
     * @return {promise}
     */
    public async verify (): Promise<boolean> {
        const tokenData = this._jwt.verify(this._token);
        if (this._ip && this._ip !== (tokenData.data || {}).ip) {
            return false;
        }
        return super.verify();
    }

    public async verifyAndRenew () : Promise<boolean> {
        if (await this.verify()) {
            await this.renew();
            return true;
        }
        return false;
    }

}