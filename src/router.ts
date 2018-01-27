import { access, constants } from 'fs';
import { Response, IResponse } from './response';
import { getParams, IParams } from '@coolgk/url';
import { IDependencies } from './controller';

export { IParams };

export interface IRouterConfig {
    url: string;
    method: string;
    urlParser?: (url: string, pattern: string) => object;
    require?: (file: string) => any;
    [key: string]: any;
    [key: number]: any;
}

export interface IModuleControllerAction {
    module: string;
    controller: string;
    action: string;
}

export class Router {
    private _options: IRouterConfig;
    private _require: (file: string) => any | undefined;
    private _moduleControllerAction: IModuleControllerAction;

    /* tslint:disable */
    /**
     * @param {object} options
     * @param {string} options.url - request.originalUrl from expressjs
     * @param {string} options.method - http request method GET POST etc.
     * @param {function} [options.urlParser] - parser for getting url params e.g. for parsing patterns like /api/user/profile/:userId optional unless you need a more advanced parser
     */
    /* tslint:enable */
    public constructor (options: IRouterConfig) {
        this._options = options;
        this._require = options.require || (require.main ? require.main.require : () => Object);
    }

    /* tslint:disable */
    /**
     * this method routes urls like /moduleName/controllerName/action/param1/params2 to file modules/modulename/controllers/controllerName.js
     * @return {promise} -
     */
    /* tslint:enable */
    public async route (): Promise<IResponse> {
        const {module, controller, action} = this.getModuleControllerAction();

        const response = new Response();
        const controllerFile = `./modules/${module}/controllers/${controller}.js`.toLowerCase();
        const controllerFileReadable = await new Promise((resolve, reject) => {
            access(controllerFile, constants.R_OK, (error) => resolve(error ? false : true));
        });

        if (controllerFileReadable) {
            const controllerObject = new (this._require(controllerFile).default)(this._options);
            const route = controllerObject.getRoutes()[this._options.method];

            // route allowed & action exists
            if (route && route[action] !== undefined && controllerObject[action]) {
                const dependencies: IDependencies = {
                    params: (this._options.urlParser || getParams)(
                        this._options.url,
                        `${module}/${controller}/${action}/${route[action]}`
                    ),
                    response,
                    services: controllerObject.getServices()
                };
                const permission = controllerObject.getPermissions()[action] || controllerObject.getPermissions()['*'];
                const accessGranted = permission ? await permission(dependencies) : true;

                if (!accessGranted) {
                    return response.status(403, 'Forbidden');
                }

                await controllerObject[action](dependencies);

                return response.getResponse();
            }
        }

        return response.status(404, 'Not Found');
    }

    public getModuleControllerAction (): IModuleControllerAction {
        // this._option.url is "request.url" from node or "request.originalUrl" from express
        let [, module, controller, action] = (this._options.url.split('?').shift() || '').split('/').map(
            // remove special characters for example . (dot)
            // dodgy url: /portix/print?page=../../../../../../../../../etc/passwd
            // and convert hyphen separated words to camelCase e.g. no-access to noAccess
            (url) => (url || 'index')
                .replace(/[^_a-zA-Z0-9\-]/g, '')
                .toLowerCase()
                .split('-')
                .map((text, index) => index ? text[0].toUpperCase() + text.substr(1) : text)
                .join('')
        );

        if (!module) {
            module = 'index';
        }

        if (!controller) {
            controller = 'index';
        }

        if (!action) {
            action = 'index';
        }

        return {module, controller, action};
    }

}

export default Router;
