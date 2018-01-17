/* import { IRoutes, IPermissions, Controller } from './controller';

export default class Example extends Controller {

    public getRoutes (): IRoutes {
        return {
            GET: {
                index: '',
                test: ':id/:name',
                csrf: ''
            },
            POST: {
                index: ':var',
                test: ''
            },
            HEAD: {
                index: '',
                test: ''
            }
        };
    }


    public getPermissions (): IPermissions {
        return {
            index: () => Promise.resolve(true),
            // test: () => Promise.resolve(1),
            // csrf: (options) => {
                // options.requireCsrfToken = false;
                // return this._services.permission.verifyAccess(options);
            // }
        };
    }

    index () {
        // return this._services.exampleModel.save({name1: '', email: ''}).then(
            // () => {
                // return this._sendJson({secuces: true});
            // },
            // () => {

            // }
        // );
        this._response.json([this._params, this._get, this._post, this._session]);
    }

    test () {
        return this._sendJson([this._params, this._get, this._post]);
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
 */