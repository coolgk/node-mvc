import { access } from 'fs';
import { Response, IResponse } from './response';

export interface IRouterConfig {
    url: string;
    method: string;
    [key: string]: any;
}

export default class Router {

    private _options: IRouterConfig;

    /**
     * @param {string} url - request.originalUrl from expressjs
     * @param {string} method - http request method GET POST etc.
     * @param {string} accessToken - access token
     */
    public constructor (options: IRouterConfig) {
        this._options = options;
    }

    /**
     * @return {promise}
     */
    public async route (): Promise<IResponse> {
        // this._option.url = request.originalUrl from express
        const [, module, controller, action] = this._options.url.split('?').shift().split('/').map(
            // remove special characters for example . (dot) dodgy url: /portix/print.php?page=../../../../../../../../../etc/passwd
            (url) => (url || 'index').replace(/[^_a-zA-Z0-9\/]/g, '')
        );

        const response = new Response();
        const controllerFile = `./modules/${module}/controllers/${controller}.js`.toLowerCase();
        const controllerExsits = await new Promise((resolve, reject) => {
            access(controllerFile, fs.constants.R_OK, (error) => resolve(error ? false : true));
        });

        if (controllerExsits) {
            const controllerInstance = new (require(controllerFile))(this._options);
            const route = controllerInstance.getRoutes()[this._options.method];

            const permission = controllerInstance.getPermissions()[action] || controllerInstance.getPermissions()['*'];
            const accessGranted = permission ? permission() : true;

            if (route && route[action] !== undefined && accessGranted && controllerInstance[action]) { // route allowed & action exists
                await controllerInstance[action]();
                return response.getResponse();
            }
        }

        return response.status(404, 'Not Found');
    }
}
