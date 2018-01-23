import { IRoutes, IPermissions, Controller, IServices } from '../../../../../controller';
import { Response } from '../../../../../response';
import { INewUser, IExistingUser } from '../models/full';
import { IParams } from '@coolgk/url';
import { access, constants } from 'fs';

export class Full extends Controller {

    public getRoutes (): IRoutes {
        return {
            GET: {
                index: '', // allow GET request to index() method
                user: ':id', // parse url param
                downloadPhoto: ':userId'
            },
            POST: {
                register: '' // allow POST request to register() method
            }
        };
    }

    public getPermissions (): IPermissions {
        return {
            // set default permission for all methods, deny accessing all methods
            // '*': () => this._options.session.verify(),
            '*': () => false,
            register: () => true, // allow accessing register() method without logging in
            login: () => true // allow accessing login() method without logging in
        };
    }

    public getServices (): IServices {
        return {
            model: new (require('../models/full').Full)(this._options.config)
        }
    }

    public login () {
        const post = await this._options.formdata.getData();
        const loggedIn = await this._services.model.authUser({username: post.username, password: post.password});
        
        if (loggedIn) {
            // this._options.session.start();
        }
    }

    // POST /example/full/register
    public async register ({response}: {response: Response}) {
        const post = await this._options.formdata.getData('photo');
        const savedUser = await this._services.model.save({
            name: post.name,
            photo: post.photo
        });
        response.json(savedUser);
    }

    // GET /example/full/user/123
    public async user ({params, response}: {params: IParams, response: Response}) {
        const user = await this._services.model.getUser(params.id);
        response.json(user);
    }

    public async downloadPhoto ({params, response}: {params: IParams, response: Response}) {
        const user = await this._services.model.getUser(params.userId);

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
