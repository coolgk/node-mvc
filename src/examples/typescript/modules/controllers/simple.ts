import { IRoutes, IPermissions, Controller } from '../../../../controller';

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
            index: () => Promise.resolve(true),
        };
    }

    index () {
        this._options.response.json(['index']);
    }

    user () {
        this._options.response.json(this._params);
    }

    public getServices () {
        return {
            // exampleModel: new (require('../models/example.mongo.js'))(),
            // permission: new (require('../../../core/permission.js'))()
        };
    }

}
