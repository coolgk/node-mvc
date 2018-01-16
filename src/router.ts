import { access, constants } from 'fs';
import { Response, IResponse } from './response';
import { getParams } from '@coolgk/url';

export interface IRouterConfig {
    url: string;
    method: string;
    urlParser?: (url: string, pattern: string) => object;
    [key: string]: any;
    [key: number]: any;
}

export class Router {
    private _options: IRouterConfig;

    /**
     * @param {object} options
     * @param {string} options.url - request.originalUrl from expressjs
     * @param {string} options.method - http request method GET POST etc.
     * @param {function} [options.urlParser] - parser for getting url params e.g. for parsing patterns like /api/user/profile/:userId optional unless you need a more advanced parser
     */
    public constructor (options: IRouterConfig) {
        this._options = options;
    }

    /**
     * @return {promise} -
     */
    public async route (): Promise<IResponse> {
        // this._option.url is "request.url" from node or "request.originalUrl" from express
        const [, module, controller, action] = (this._options.url.split('?').shift() || '').split('/').map(
            // remove special characters for example . (dot)
            // dodgy url: /portix/print?page=../../../../../../../../../etc/passwd
            (url) => (url || 'index').replace(/[^_a-zA-Z0-9\/]/g, '')
        );

        const response = new Response();
        const controllerFile = `./modules/${module}/controllers/${controller}.js`.toLowerCase();
        const controllerFileReadable = await new Promise((resolve, reject) => {
            access(controllerFile, constants.R_OK, (error) => resolve(error ? false : true));
        });

        if (controllerFileReadable) {
            const controllerInstance = new (require(controllerFile))(this._options);
            const route = controllerInstance.getRoutes()[this._options.method];

            const permission = controllerInstance.getPermissions()[action] || controllerInstance.getPermissions()['*'];
            const accessGranted = permission ? await permission() : false;

            const params = (this._options.urlParser || getParams)(
                this._options.url,
                `${module}/${controller}/${action}/${route[action]}`
            );

            // route allowed & permission granted & action exists
            if (route && route[action] !== undefined && accessGranted && controllerInstance[action]) {
                await controllerInstance[action](this._options, params, response);
                return response.getResponse();
            }
        }

        return response.send('Not Found', 404);
    }
}

export default Router;
