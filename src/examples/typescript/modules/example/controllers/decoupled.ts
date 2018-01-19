import { IRoutes, IPermissions, Controller } from '../../../../../controller';
import { IResponse } from '../../../../../response';

export class Decoupled extends Controller {

    public getRoutes (): IRoutes {
        return {
            GET: {
                index: '', // allow GET request to index() method
                user: ':id/:section' // access url param
            },
            POST: {
                save: '' // allow POST request to save() method
            }
        };
    }

    public getPermissions (): IPermissions {
        return {
            '*': () => true, // check permissions here
            user: () => Promise.resolve(true), // e.g if logged in or have permission to access this url after logged in
            noAccess: () => false, // deny access
        };
    }

    // GET /example/simple
    index ({response}: {response: IResponse}) {
        response.json(['index']);
    }

    // GET /example/simple/user/123/preference
    user ({params, response}: {params: object, response: IResponse}) {
        response.json(params);
    }

    // POST /example/simple/internal
    save ({response}: {response: IResponse}) {
        response.json(['save']);
    }

    // false returned in getPermissions()
    // GET /example/simple/user/123/no-access
    // 403 Forbidden
    noAccess () {

    }

    // Not defined in getRoutes()
    // GET /example/simple/internal
    // 404 Not Found
    internal () {

    }

}

export default Decoupled;
