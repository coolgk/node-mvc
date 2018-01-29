import { access, constants } from 'fs';
import { Response, IResponse } from './response';
import { getParams, IParams } from '@coolgk/url';
import { IDependencies } from './controller';

export { IParams };

export interface IRouterConfig {
    url: string;
    method: string;
    rootDir: string;
    urlParser?: (url: string, pattern: string) => IParams;
    [key: string]: any;
    [key: number]: any;
}

export interface IModuleControllerAction {
    module: string;
    controller: string;
    action: string;
    originalModule: string;
    originalController: string;
    originalAction: string;
}

export enum RouterError {
    Not_Found_404 = 'Not Found',
    Forbidden_403 = 'Forbidden'
}

export class Router {
    private _options: IRouterConfig;

    /* tslint:disable */
    /**
     * @param {object} options
     * @param {string} options.url - request.originalUrl from expressjs
     * @param {string} options.method - http request method GET POST etc
     * @param {string} options.rootDir - rood dir of the app
     * @param {function} [options.urlParser] - parser for getting url params e.g. for parsing patterns like /api/user/profile/:userId optional unless you need a more advanced parser
     */
    /* tslint:enable */
    public constructor (options: IRouterConfig) {
        this._options = options;
    }

    /* tslint:disable */
    /**
     * this method routes urls like /moduleName/controllerName/action/param1/params2 to file modules/modulename/controllers/controllerName.js
     * @return {promise} - returns a controller method's return value if the return value is not falsy otherwise returns standard response object genereated from the response methods called inside the controller methods e.g. response.json({...}), response.file(path, name) ...see code examples in decoupled.ts/js or full.ts/js
     */
    /* tslint:enable */
    public async route (): Promise<IResponse> {
        const { module, controller, action, originalModule, originalController, originalAction } = this.getModuleControllerAction();

        const response = new Response();
        const controllerFile = `${this._options.rootDir}/modules/${module}/controllers/${controller}.js`.toLowerCase();
        const controllerFileReadable = await new Promise((resolve, reject) => {
            access(controllerFile, constants.R_OK, (error) => resolve(error ? false : true));
        });

        if (controllerFileReadable) {
            const controllerObject = new (require(controllerFile).default)(this._options);
            const route = controllerObject.getRoutes()[this._options.method];

            // route allowed & action exists
            if (route && route[action] !== undefined && controllerObject[action]) {
                const dependencies: IDependencies = {
                    params: (this._options.urlParser || getParams)(
                        this._options.url,
                        `${originalModule}/${originalController}/${originalAction}/${route[action]}`
                    ),
                    response,
                    services: controllerObject.getServices()
                };
                const permission = controllerObject.getPermissions()[action] || controllerObject.getPermissions()['*'];
                const accessGranted = typeof(permission) === 'function' ? await permission(dependencies) : true;

                if (!accessGranted) {
                    return response.text(RouterError.Forbidden_403, 403);
                }

                return await controllerObject[action](dependencies) || response.getResponse();
            }
        }

        return response.text(RouterError.Not_Found_404, 404);
    }

    public getModuleControllerAction (): IModuleControllerAction {
        // this._option.url is "request.url" from node or "request.originalUrl" from express
        const [, originalModule, originalController, originalAction] = (this._options.url.split('?').shift() || '').split('/');

        return {
            module: this._sanatise(originalModule),
            controller: this._sanatise(originalController),
            action: this._sanatise(originalAction),
            originalModule,
            originalController,
            originalAction
        };
    }

    /**
     * filter out malicious characters from the url e.g. . (dot) from /portix/print?page=../../../../../../../../../etc/passwd
     * and convert hyphen-separated-case to camelCase e.g. no-access becomes noAccess
     * @ignore
     * @private
     * @param {string} moduleControllerAction - original module, controller or action string from the url
     * @returns {string}
     * @memberof Router
     */
    private _sanatise (moduleControllerAction: string): string {
        return (moduleControllerAction || 'index')
            .replace(/[^_a-zA-Z0-9\-]/g, '')
            .toLowerCase()
            .split('-')
            .map((text, index) => index ? text[0].toUpperCase() + text.substr(1) : text)
            .join('');
    }
}

export default Router;
