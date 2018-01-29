import { IParams } from '@coolgk/url';
import { Response } from './response';

export interface IRoutes {
    [key: string]: {
        [propName: string]: string
    };
}

export interface IPermissions {
    [key: string]: () => Promise<boolean> | boolean;
}

export interface IDependencies {
    params: IParams;
    response: Response;
    services: any;
}

/**
 * Base controller class
 */
export class Controller {

    protected _options: any;

    /**
     * @param {*} [options] - any global dependencies to pass into controllers from the entry point
     * @memberof Controller
     */
    constructor (options?: any) {
        this._options = options;
    }

    /* tslint:disable */
    /**
     * @returns {object} - allowable routes to access controller methods. Format: { [HTTP_METHOD]: { [CLASS_METHOD_NAME]: [PARAM_PATTERN], ... } }
     * @memberof Controller
     */
    /* tslint:enable */
    public getRoutes (): IRoutes {
        return {};
    }

    /* tslint:disable */
    /**
     * @returns {object} - a callback, which should return a boolean or Promise<boolean> value, for controlling the access of controller methods. Format: { [CLASS_METHOD_NAME]: [CALLBACK], ... }
     * @memberof Controller
     */
    /* tslint:enable */
    public getPermissions (dependencies?: IDependencies): IPermissions {
        return {};
    }

    /* tslint:disable */
    /**
     * @returns {object} - class dependencies which are passed into class methods as one of the arguments
     * @memberof Controller
     */
    /* tslint:enable */
    public getServices (): any {
        return {};
    }

}

export default Controller;
