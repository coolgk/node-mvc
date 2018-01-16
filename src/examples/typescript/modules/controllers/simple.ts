import { IRoutes, IPermissions, Controller } from './controller';

export class Simple extends Controller {

    public getRoutes (): IRoutes {
        return {
            GET: {
                index: ''
            },
            POST: {
                save: ''
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

    csrf () {
        return this._sendJson([this._session]);
    }

    protected _getServices () {
        return {
            exampleModel: new (require('../models/example.mongo.js'))(),
            permission: new (require('../../../core/permission.js'))()
        };
    }

}

module.exports = Example;
