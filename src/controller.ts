import { DI, IServices } from './di';

export interface IConfig {
    [key: string]: any;
}

export interface IRoutes {
    [key: string]: { [propName: string]: string };
}

export interface IPermissions {
    [key: string]: Promise<boolean>;
}

export class Controller extends DI {

    protected _options: IConfig;

    constructor (options： IConfig = {}) {
        super();
        this._options = options;
    }

    public getRoutes (): IRoutes {
        return {};
    }

    public getPermissions (): IPermissions {
        return {};
    }

    public _getServices (): IServices {
        return {};
    }

}
