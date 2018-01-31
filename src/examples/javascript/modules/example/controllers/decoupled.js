'use strict';
/**
 * an example controller using the @coolgk/mvc framework which decouples express from the main controller code
 */
const { Controller } = require('@coolgk/mvc/controller');

/**
 * controller classes should extend the Controller class from @coolgk/mvc/controller
 * you can also create your own base controller that extends @coolgk/mvc/controller
 */
class Decoupled extends Controller {
    /**
     * setup valid routes to methods
     */
    getRoutes () {
        return {
            GET: {
                index: '', // allow GET request to call the index() method
                user: ':id/:section', // allow GET request to call the user() method and id, section are the parameters in url
                customData: '' // allow GET request "custom-data" to call customData() method
            },
            POST: {
                save: '' // allow POST request to call the save() method
            }
        };
    }

    /**
     * setup permission callbacks for accessing methods
     */
    getPermissions () {
        return {
            // * is the default permission for all methods in this class
            // allow requests to access all methods
            '*': () => true,
            'user': () => Promise.resolve(true), // the callback can also return a promise<boolean>
            'noAccess': () => false // deny all access
        };
    }

    /**
     * HTTP Request:
     * GET /example/decoupled
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.response - reponse object injected by the router
     */
    index ({ response }) {
        // send a json response
        // response need to be handled manually out after calling Router.route()
        response.json(['index']);
    }

    /**
     * HTTP Request:
     * GET /example/decoupled/custom-data
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.response - reponse object injected by the router
     */
    customData ({ response }) {
        // send a response with arbitrary data
        // response need to be handled manually out after calling Router.route()
        response.send({
            anything: 1,
            can: 'text',
            be: [1],
            here: {
                ok: 'ok'
            }
        });
    }

    /**
     * HTTP Request:
     * GET /example/decoupled/user/1234/preference
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.params - url param values configured in getRoutes()
     * @param {object} dependencies.response - reponse object injected by the router
     */
    user ({ params, response }) {
        // send a json response
        // with the request /example/extended/user/1234/preference
        // the params variable contains value { id: '1234', section: 'preference' }
        response.json(params);
    }

    /**
     * HTTP Request:
     * POST /example/decoupled/save
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.response - reponse object injected by the router
     */
    save ({ response }) {
        // send a json response
        response.json(['save']);
    }

    /**
     * HTTP Request: /example/simple/no-access
     */
    noAccess () {
        // the callback in getPermissions() for the noAccess() method returns false
        // router will return a 403 Forbidden response
    }

    /**
     * HTTP Request: /example/simple/internal
     */
    internal () {
        // internal is not defined in getRoutes() i.e. this method no accessible through a request
        // router will return a 404 Not Found response
    }
}

exports.default = Decoupled;
