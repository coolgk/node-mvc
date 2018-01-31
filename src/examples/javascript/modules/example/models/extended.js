'use strict';
/**
 * a dummy model class
 * "Extended" is the name of the class
 */
class Extended {

    constructor (config) {
        this._config = config;
    }

    /**
     * authenticate user
     * dummy method, always returns true
     */
    async authUser () {
        return true;
    }

    /**
     * dummpy method for saving user to db
     */
    async save (data) {
        return Object.assign({ _id: '5a0d6d152fff6d00c592aa9e' }, data);
    }

    /**
     * dummy method for querying user data from db
     */
    async getUser (userId) {
        return {
            _id: '5a0d6d152fff6d00c592aa9e',
            name: 'Daniel Gong',
            photo: this._config.uploadDir + '/15172676018296279OvFNrONRZp2w'
        };
    }

}

exports.default = Extended;
