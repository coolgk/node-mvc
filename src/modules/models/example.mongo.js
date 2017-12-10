'use strict';

/*
sample collection data

ExampleCollection
{
    string: 'this is a string',

    money: 1.23,

    float_number: 3123.2312,

    integer: 12312,

    large_integer: 1231231231231231231231238123818238123812831823,

    db_ref: DBRef(...),

    enum: 'predefined_value_1',

    array_of_DBRef: [
        DbRef(...), DbRef(...), ...
    ],

    array_of_float: [
        1.1, 1.3, ...
    ],

    array_of_enum: [
        'predefined_value_1', ...
    ],

    object: {
        field_name: 'string',
        ...
    }

    array_of_objects: [
        {
            name: '...string',
            ...
        }
    ]
}

date, datetime, time

*/

class ExampleModel extends require.main.require('./core/db/mongo.js') {

    constructor () {
        super();

        // escaped string, html tags are escaped
        this._setField('string', {dataType: 'string'});

        // keep html in the database
        this._setField('html', {
            dataType: 'string',
            setter: (value) => value
        });

        // keep html in the database
        this._setField('field_with_default_value', {
            dataType: 'string',
            setter: (value) => value,
            defaultValue: 'abc'
        });

        this._setField('date', {dataType: 'date'});
        this._setField('yes_no', {dataType: 'boolean'});

        this._setField('money', {dataType: 'number'});
        this._setField('float_number', {dataType: 'number'});
        this._setField('integer', {dataType: 'number'});
        this._setField('large_integer', {dataType: 'number'});

        this._setField('user_id_dbref', {
            dataType: 'dbRef',
            model: require('../models/user.js')
        });

        this._setField('enum', {
            dataType: 'enum',
            enum: [
                'predefined_value_1',
                'predefined_value_2'
            ]
        });

        this._setField('array_of_DBRef', {dataType: 'dbRef', multiple: true});
        this._setField('array_of_numbers', {dataType: 'number', multiple: true});

        this._setField('array_of_enum', {
            dataType: 'enum',
            enum: [
                'predefined_value_1',
                'predefined_value_2'
            ],
            multiple: true
        });

        this._setField('object', {
            dataType: 'object',
            object: {
                field_name: {
                    dataType: 'string'
                }
                // ,...
            }
        });

        this._setField('array_of_objects', {
            dataType: 'object',
            object: {
                field_name: {
                    dataType: 'string'
                }
                // ,...
            },
            multiple: true
        });
    }

    static getCollectionName () {
        return 'ExampleCollection';
    }

    saveMethod () {
        /*
            model.save() example

            {
                objectItems: [
                    {
                        _id: ObjectId(...),
                        a: 1,
                        b: 2,
                        ...
                    }
                ],
                arrayItems: [1, 2, 3],
                normalValue: 'a',
                ...
            }

            // below query inserts a new item into the objectItems array
            model.save({
                objectItems: [{a: 3, b: 4}, {a: 6, b: 7}],
                arrayItems: [4, 5]
            });

            // after the query, data look like
            {
                objectItems: [
                    { _id: ObjectId(...), a: 1, b: 2, ... },
                    { _id: ObjectId(...), a: 3, b: 4, dateCreated: ..., dateModified: ... } //_id, dateCreated, dateModified are automatically created
                    { _id: ObjectId(...), a: 6, b: 7, dateCreated: ..., dateModified: ... }
                ],
                arrayItems: [1,2,3,4,5]
            }

            // to remove items from arrays
            model.save({
                objectItems: { $remove: [ObjectId(ID_OF_THE_LAST_ITEM)] },
                arrayItems: { $remove: [1, 5] }
            });

            // after the query, data look like
            {
                objectItems: [
                    { _id: ObjectId(...), a: 1, b: 2, ... },
                    { _id: ObjectId(...), a: 3, b: 4, dateCreated: ..., dateModified: ... } //_id, dateCreated, dateModified are automatically created
                ],
                arrayItems: [2,3,4]
            }

            // run both add and remove (remove one and add more)
            model.save({
                _id: ObjectId(...),
                objectItems: { $remove: [ObjectId(ID_AN_ITEM)], $update: [{a: 8, b: 9}] },
                arrayItems: { $remove: [1, 5], $update: [9]]  }
            });

            // update array items, pass the _id of the item in the array, this will update the array item with that id
            model.save({
                _id: ObjectId(...),
                objectItems: [{_id: ObjectId(...), a: 'new value', b: 'new value'}]
            });
        */
    }

    findAllMethod () {
        /**
         * @param {object} options
         * @param {object} [options.filters={}] - e.g. { _id: ObjectId('...'), name: '...' }
         * @param {object} [options.fields=false] - 1 = select, 0 = deselect e.g. {username: 1, password: 0}
         * @param {object} [options.dbRefs=false] - dbRef data to attach e.g. { company: {name: 1} } which will replace company dbrefs value with name
         * @param {object} [options.sort=false] - { ascending : 1, descending: -1 } or [[field1, 1], [field2, -1]] (array enforces ordering of sort keys)
         * @param {number} [options.limit=0] - number of rows to return
         * @param {number} [options.skip=0] - number of rows to skip
         * @param {bool} [options.count=false] - if to include total count (skip & limit are ignored for counting)
         * @param {bool} [options.cursor=false] - if to return result.data as cursor
         */
        /*
        this.findAll({
            filters: { status: 'deleted' },
            fields: { name: 1, dateModified: 1 },
            dbRefs: {
                company: { name: 1 }
            },
            sort: {
                _id: -1
            },
            limit: 10,
            skip: 0,
            count: true
        });

        */
    }
}

module.exports = ExampleModel;
