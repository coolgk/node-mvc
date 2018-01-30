/**
 * an example controller using the @coolgk/mvc framework
 */
import { IRoutes, IPermissions, Controller, IDependencies } from '@coolgk/mvc/controller';
import { INewUser, IExistingUser } from '../models/extended';
import { access, constants } from 'fs';

/**
 * controller classes should extend the Controller class from @coolgk/mvc/controller
 * you can also create your own base controller that extends @coolgk/mvc/controller
 */
export class Extended extends Controller {
    /**
     * setup valid routes to methods
     */
    public getRoutes (): IRoutes {
        return {
            GET: {
                user: ':id', // allow GET request to call the user() method
                downloadPhoto: ':userId', // allow GET request to call the downloadPhoto() method
                logout: '' // allow GET request to call the logout() method
            },
            POST: {
                register: '', // allow POST request to call register() method
                login: '' // allow POST request to call login() method
            }
        };
    }

    /**
     * setup permission callbacks for accessing methods
     */
    public getPermissions (): IPermissions {
        return {
            // * the is default permission for all methods in this class
            // deny if not logged in, otherwise renew session and allow access
            // see @coolgk/session https://www.npmjs.com/package/@coolgk/session
            '*': () => this._options.session.verifyAndRenew(),
            // skip session check for the register() method
            'register': () => true,
            // the callback can also return a promise<boolean>
            'login': () => Promise.resolve(true)
        };
    }

    /**
     * setup all dependencies
     */
    public getServices (): any {
        return {
            model: new (require('../models/extended').default)(this._options.config)
        };
    }

    /**
     * HTTP Request:
     * POST /example/extended/login
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.response - reponse object injected by the router
     * @param {*} dependencies.services - services from returned from getServices() injected by the router
     */
    public async login ({response, services}: IDependencies) {
        // get form data
        // see @coolgk/formdata https://www.npmjs.com/package/@coolgk/formdata
        const post = await this._options.formdata.getData();

        if (!post.username || !post.password) {
            response.json({error: 'username and password are required'});
            return;
        }

        // call the authUser() method from the model (dependency)
        const loggedIn = await services.model.authUser({username: post.username, password: post.password});

        if (loggedIn) {
            // start a session
            const accessToken = await this._options.session.init();
            // set session data
            await this._options.session.set('user', {username: post.username, password: post.password});
            // set response
            response.json({ accessToken });
        }
    }

    /**
     * HTTP Request:
     * GET /example/extended/logout
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.response - reponse object injected by the router
     */
    public async logout ({response}: IDependencies) {
        // kill the current session and set response
        response.json(await this._options.session.destroy());
    }

    /**
     * HTTP Request:
     * POST /example/extended/register
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.response - reponse object injected by the router
     * @param {*} dependencies.services - services from returned from getServices() injected by the router
     */
    public async register ({response, services}: IDependencies) {
        // get posted data and uploaded file
        // see @coolgk/formdata https://www.npmjs.com/package/@coolgk/formdata
        const post = await this._options.formdata.getData('photo');

        // call model's method
        const savedUser = await services.model.save({
            name: post.name,
            photo: post.photo
        });

        // set response
        response.json(savedUser);
    }

    /**
     * HTTP Request:
     * GET /example/extended/user/1234
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.params - url param values configured in getRoutes()
     * @param {object} dependencies.response - reponse object injected by the router
     * @param {*} dependencies.services - services from returned from getServices() injected by the router
     */
    public async user ({params, response, services}: IDependencies) {
        // user() method has :id configured as a param in getRoutes()
        if (!params.id) {
            response.json({error: 'missing user id'});
            return;
        }

        // call model's method
        const user = await services.model.getUser(params.id);

        // send user data and all data in session to response
        response.json({ user, session: await this._options.session.getAll() });
    }

    /**
     * HTTP Request:
     * GET /example/extended/download-photo
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.params - url param values configured in getRoutes()
     * @param {object} dependencies.response - reponse object injected by the router
     * @param {*} dependencies.services - services from returned from getServices() injected by the router
     */
    public async downloadPhoto ({params, response, services}: IDependencies) {
        // find the file path from model
        const user = await services.model.getUser(params.userId);

        return new Promise((resolve) => {
            access(user.photo, constants.R_OK, (error) => {
                if (error) {
                    response.text('File Not Found', 404);
                } else {
                    response.file(user.photo, 'photo.jpg');
                }
                resolve();
            });
        });
    }

}

export default Extended;
