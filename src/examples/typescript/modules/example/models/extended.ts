import { IConfig } from '../../../config';

export interface INewUser {
    name: string;
    photo: string;
}

export interface IExistingUser extends INewUser {
    _id: string;
}

export class Extended {

    private _config: IConfig;

    public constructor (config: IConfig) {
        this._config = config;
    }

    public async authUser () {
        return true;
    }

    public async save (data: INewUser): Promise<IExistingUser> {
        return {
            _id: '5a0d6d152fff6d00c592aa9e',
            ...data
        };
    }

    public async getUser (userId: string): Promise<IExistingUser> {
        return {
            _id: '5a0d6d152fff6d00c592aa9e',
            name: 'Daniel Gong',
            photo: this._config.uploadDir + '/15172676018296279OvFNrONRZp2w'
        };
    }

}

export default Extended;
