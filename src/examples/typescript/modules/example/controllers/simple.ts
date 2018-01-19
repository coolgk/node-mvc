import { IRoutes, IPermissions, Controller } from '../../../../../controller';

export class Simple extends Controller {

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
            '*': () => true, // set permission for all methods, allow anyone to access all methods
            user: () => Promise.resolve(true), // e.g if logged in or have permission to access this url after logged in
            noAccess: () => false, // deny access
        };
    }

    // GET /example/simple
    index () {
        this._options.response.json(['index']);
    }

    // GET /example/simple/user/123/preference
    user ({params}: {params: object}) {
        this._options.response.json(params);
    }

    // POST /example/simple/internal
    save () {
        this._options.response.json(['save']);
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

export default Simple;
