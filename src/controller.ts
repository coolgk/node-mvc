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

export class Controller {

    protected _options: any;
    protected _services: IServices;

    constructor (options: any) {
        this._options = options;
        this._services = this.getServices();
    }

    public getRoutes (): IRoutes {
        return {};
    }

    public getPermissions (): IPermissions {
        return {};
    }

    public getServices (): IServices {
        return {};
    }

}

export default Controller;
