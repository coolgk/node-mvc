import { IParams } from '@coolgk/url';
import { Response } from './response';

export interface IRoutes {
    [key: string]: {
        [propName: string]: string
    };
}

export interface IServices {
    [key: string]: any;
}

export interface IPermissions {
    [key: string]: () => Promise<boolean> | boolean;
}

export interface IDependencies {
    params: IParams;
    response: Response;
    services: IServices;
}

export class Controller {

    protected _options: any;

    constructor (options: any) {
        this._options = options;
    }

    public getRoutes (): IRoutes {
        return {};
    }

    public getPermissions (dependencies?: IDependencies): IPermissions {
        return {};
    }

    public getServices (): IServices {
        return {};
    }

}

export default Controller;
