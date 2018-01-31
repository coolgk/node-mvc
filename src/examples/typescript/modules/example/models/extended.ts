import { IConfig } from '../../../config';

export interface INewUser {
    name: string;
    photo: string;
}

export interface IExistingUser extends INewUser {
    _id: string;
}

/**
 * a dummy model class
 * "Extended" is the name of the class
 */
export class Extended {

    private _config: IConfig;

    public constructor (config: IConfig) {
        this._config = config;
    }

    /**
     * authenticate user
     * dummy method, always returns true
     */
    public async authUser (): Promise<boolean> {
        return true;
    }

    /**
     * dummpy method for saving user to db
     */
    public async save (data: INewUser): Promise<IExistingUser> {
        return {
            _id: '5a0d6d152fff6d00c592aa9e',
            ...data
        };
    }

    /**
     * dummy method for querying user data from db
     */
    public async getUser (userId: string): Promise<IExistingUser> {
        return {
            _id: '5a0d6d152fff6d00c592aa9e',
            name: 'Daniel Gong',
            photo: this._config.uploadDir + '/15172676018296279OvFNrONRZp2w'
        };
    }

}

export default Extended;
