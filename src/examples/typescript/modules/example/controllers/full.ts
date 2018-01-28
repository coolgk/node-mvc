import { IRoutes, IPermissions, Controller, IServices, IDependencies } from '../../../../../controller';
import { INewUser, IExistingUser } from '../models/full';
import { access, constants } from 'fs';

export class Full extends Controller {

    public getRoutes (): IRoutes {
        return {
            GET: {
                user: ':id', // allow GET request to user() method
                downloadPhoto: ':userId',
                logout: ''
            },
            POST: {
                register: '', // allow POST request to register() method
                login: '' // allow POST request to register() method
            }
        };
    }

    public getPermissions (): IPermissions {
        return {
            // set default permission for all methods, deny if not logged in
            '*': () => this._options.session.verifyAndRenew(),
            'register': () => true, // allow accessing register() method without logging in
            'login': () => true // allow accessing login() method without logging in
        };
    }

    public getServices (): IServices {
        return {
            model: new (require('../models/full').Full)(this._options.config)
        };
    }

    /**
     *
     * @param param0
     */
    public async login ({response, services}: IDependencies) {
        const post = await this._options.formdata.getData();

        if (!post.username || !post.password) {
            response.json({error: 'username and password are required'});
            return;
        }

        const loggedIn = await services.model.authUser({username: post.username, password: post.password});

        if (loggedIn) {
            const accessToken = await this._options.session.init();
            await this._options.session.set('user', {username: post.username, password: post.password});
            response.json({ accessToken });
        }
    }

    public async logout ({response}: IDependencies) {
        response.json(await this._options.session.destroy());
    }

    // POST /example/full/register
    public async register ({response, services}: IDependencies) {
        const post = await this._options.formdata.getData('photo');
        const savedUser = await services.model.save({
            name: post.name,
            photo: post.photo
        });
        response.json(savedUser);
    }

    // GET /example/full/user/123
    public async user ({params, response, services}: IDependencies) {
        if (!params.id) {
            response.json({error: 'missing user id'});
            return;
        }
        const user = await services.model.getUser(params.id);
        response.json({ user, session: await this._options.session.getAll() });
    }

    public async downloadPhoto ({params, response, services}: IDependencies) {
        const user = await services.model.getUser(params.userId);

        return new Promise((resolve) => {
            access(user.photo, constants.R_OK, (error) => {
                if (error) {
                    response.status(404, 'File Not Found');
                } else {
                    response.file(user.photo, 'photo.jpg');
                }
                resolve();
            });
        });
    }

}

export default Full;
