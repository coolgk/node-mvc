/**
 * an example controller of @coolgk/mvc framework
 */
import { IRoutes, IPermissions, Controller, IDependencies } from '@coolgk/mvc/controller';
import { INewUser, IExistingUser } from '../models/extended';
import { access, constants } from 'fs';

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
     * setup permissions for accessing methods
     */
    public getPermissions (): IPermissions {
        return {
            // * is default permission for all methods in this class
            // deny if not logged in otherwise renew session and allow access
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
     */
    public async logout ({response}: IDependencies) {
        // kill the current session and set response
        response.json(await this._options.session.destroy());
    }

    /**
     * HTTP Request:
     * POST /example/extended/register
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
