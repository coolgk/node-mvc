import { IRoutes, IPermissions, Controller, IDependencies } from '../../../../../controller';

export class Decoupled extends Controller {

    public getRoutes (): IRoutes {
        return {
            GET: {
                index: '', // allow GET request to index() method
                user: ':id/:section', // parse url param
                customData: ''
            },
            POST: {
                save: '' // allow POST request to save() method
            }
        };
    }

    public getPermissions (): IPermissions {
        return {
            '*': () => true, // set permission for all methods, allow anyone to access all methods
            'user': () => Promise.resolve(true), // e.g if logged in or have permission to access this url / method
            'noAccess': () => false, // deny access
        };
    }

    // GET /example/decoupled
    public index ({response}: IDependencies) {
        response.json(['index']);
    }

    // GET /example/decoupled/custom-data
    public customData ({response}: IDependencies) {
        response.send({
            anything: 1,
            can: 'text',
            be: [1],
            here: {
                ok: 'ok'
            }
        });
    }

    // GET /example/decoupled/user/123/preference
    public user ({params, response}: IDependencies) {
        response.json(params);
    }

    // POST /example/decoupled/internal
    public save ({response}: IDependencies) {
        response.json(['save']);
    }

    /* tslint:disable */
    // false returned in getPermissions()
    // GET /example/decoupled/user/123/no-access
    // 403 Forbidden
    public noAccess () {

    }

    // Not defined in getRoutes()
    // GET /example/decoupled/internal
    // 404 Not Found
    private internal () {

    }
    /* tslint:enable */
}

export default Decoupled;
