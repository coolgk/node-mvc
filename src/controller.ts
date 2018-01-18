import { DI, IServices } from './di';
// import { Response } from './response';

export interface IRoutes {
    [key: string]: {
        [propName: string]: string
    };
}

export interface IPermissions {
    [key: string]: () => Promise<boolean> | boolean;
}

export class Controller extends DI {

    protected _options: any;
    // protected _response: Response | undefined;
    // protected _params: {} = {};

    constructor (options: any) {
        super();
        this._options = options;
    }

    public getRoutes (): IRoutes {
        return {};
    }

    public getPermissions (): IPermissions {
        return {};
    }

}

export default Controller;
