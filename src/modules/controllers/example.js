'use strict';

// lowercase file name

class Example extends require('../../../core/controller.js') {

    static getRoutes () {
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

    static _getServices () {
        return {
            exampleModel: new (require('../models/example.mongo.js'))(),
            permission: new (require('../../../core/permission.js'))()
        };
    }

    getPermissions () {
        return {
            // index: () => Promise.resolve(1),
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
        return this._sendJson([this._params, this._get, this._post, this._session]);
    }

    test () {
        return this._sendJson([this._params, this._get, this._post]);
    }

    csrf () {
        return this._sendJson([this._session]);
    }
}

module.exports = Example;
