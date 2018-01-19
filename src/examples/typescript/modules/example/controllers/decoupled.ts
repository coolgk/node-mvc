import { IRoutes, IPermissions, Controller } from '../../../../../controller';
import { IResponse } from '../../../../../response';

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
            user: () => Promise.resolve(true), // e.g if logged in or have permission to access this url after logged in
            noAccess: () => false, // deny access
        };
    }

    // GET /example/decoupled
    index ({response}: {response: IResponse}) {
        response.json(['index']);
    }

    // GET /example/decoupled/custom-data
    customData ({response}: {response: IResponse}) {
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
    user ({params, response}: {params: object, response: IResponse}) {
        response.json(params);
    }

    // POST /example/decoupled/internal
    save ({response}: {response: IResponse}) {
        response.json(['save']);
    }

    // false returned in getPermissions()
    // GET /example/decoupled/user/123/no-access
    // 403 Forbidden
    noAccess () {

    }

    // Not defined in getRoutes()
    // GET /example/decoupled/internal
    // 404 Not Found
    internal () {

    }

}

export default Decoupled;
