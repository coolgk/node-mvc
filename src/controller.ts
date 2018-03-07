/*!
 *  Copyright (c) 2017 Daniel Gong <daniel.k.gong@gmail.com>. All rights reserved.
 *  Licensed under the MIT License.
 */

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

export { IParams, Response };

export interface IDependencies {
    params: IParams;
    response: Response;
    globals: any;
    services?: any;
}

/**
 * Base controller class
 */
export class Controller {

    /* tslint:disable */
    /**
     * @returns {object} - routes that can access controller methods. Format: { [HTTP_METHOD]: { [CLASS_METHOD_NAME]: [PARAM_PATTERN], ... } }
     * @memberof Controller
     */
    /* tslint:enable */
    public getRoutes (): IRoutes {
        return {};
    }

    /* tslint:disable */
    /**
     * @param {object} dependencies - global dependencies passed into the router's controller
     * @returns {object} - { [CLASS_METHOD_NAME]: [CALLBACK], ... } the callback should return a boolean or Promise<boolean>
     * @memberof Controller
     */
    /* tslint:enable */
    public getPermissions (dependencies?: IDependencies): IPermissions {
        return {};
    }

    /**
     * @param {object} dependencies - global dependencies passed into the router's controller
     * @returns {object} - class dependencies, which is injected into the class methods by the router
     * @memberof Controller
     */
    public getServices (dependencies?: IDependencies): any {
        return {};
    }

}

export default Controller;
