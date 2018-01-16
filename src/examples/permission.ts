'use strict';

class Permission extends require('./db/mongo.js') {
    /*
    const _PERMISSIONS = [
        {
            name: 'dashboard',
            view: {
                value: 1,
                paths: [
                    'module/controller/action'
                ]
            },
            edit: {

            },
            create: {

            },
            delete: {

            }
            items: [
                {
                    name: 'topsites',
                    view: {

                    }
                }
            ]
        },
        {
            label: 'Building Groups',
            items: [
                {
                    label: 'group name',
                    type: 'building.group._id',
                    actions: [],
                    view: 1,
                    edit: 1,
                    remove: 1
                }
            ]
        },
        {
            label: 'Admin',
            items: [
            {
                label: 'company',
                module: 'admin',
                controller: 'company',
                actions: [],
            }
            ]
        }
    ];
    */
    constructor () {
        super();
        // this._setCollection(Permission.getCollectionName());
    }

    static getCollectionName () {
        return 'permission';
    }

    verifyAccess (options) {
        return options.session.verify().then(({error}) => {
            if (error) {
                return false;
            } else if (options.session.user) {
                if (options.requireCsrfToken ? options.csrfToken && options.csrfToken === options.session.user.csrfToken : true) {
                    const isCappAdmin = options.module === 'capp' && [
                        'deleteRuleset',
                        'saveRuleset',
                        'createComponent',
                        'deleteComponent'
                    ].includes(options.action);

                    if (options.module === 'admin' || isCappAdmin) {
                        if (options.adminModuleWhiteList.includes(options.ip) && options.session.user.isAdmin) {
                            return true;
                        }
                    } else {
                        return true;
                    }
                }
            }
            return false;
        });
    }
}

module.exports = Permission;
