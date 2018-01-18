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
            '*': () => true, // check permissions here
            user: () => Promise.resolve(true), // e.g if logged in or have permission to access this url after logged in
            noAccess: () => false, // deny access
        };
    }

    // GET /example/simple
    index () {
        this._options.response.json(['index']);
    }

    // GET /example/simple/user/123/preference
    user (params, response) {
        this._options.response.json(params);
    }

    // POST /example/simple/internal
    save () {
        this._options.response.json(['save']);
    }

    // GET /example/simple/user/123/no-access
    noAccess () {

    }

    // Not defined in getRoutes()
    // 404 when accessing /example/simple/internal
    internal () {

    }

}

export default Simple;
