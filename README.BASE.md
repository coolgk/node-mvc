# @coolgk/mvc

`npm install @coolgk/mvc`

A light javascript / typescript mvc framework that helps you to create object oriented, modulised and testable code.

[![Build Status](https://travis-ci.org/coolgk/node-mvc.svg?branch=master)](https://travis-ci.org/coolgk/node-mvc) [![Coverage Status](https://coveralls.io/repos/github/coolgk/node-mvc/badge.svg?branch=develop)](https://coveralls.io/github/coolgk/node-mvc?branch=develop) [![dependencies Status](https://david-dm.org/coolgk/node-mvc/status.svg)](https://david-dm.org/coolgk/node-mvc) [![Known Vulnerabilities](https://snyk.io/test/github/coolgk/node-mvc/badge.svg)](https://snyk.io/test/github/coolgk/node-mvc)

## How this works

This framework routes HTTP requests to class methods.

e.g.
**GET /shop/product/description/1** calls the **description** method in **/modules/api/controllers/product.js** (see example code below)

In this example request, **shop** is a module (folder), **product** is a controller (file), **description** is an action (method) and **1** is an parameter i.e. the format of the request is **/module/[controller]/[action]/[param]** and the router will try to find the file from the folder structure below:

    .
    ./modules
        /shop
            /controllers
                product.js
            /models
                model.js
        /anothermodule
            ...

**product.js**

```javascript
class Product {
    description ({ params, services }) {
        // params contains values based on the pattern configured in getRoutes()
        this._options.express.response.json(
            services.model.find(params.id)
        );
    }

    getRoutes () {
        return {
            GET: {
                description: ':id' // allow GET request to access the description() method
            }
        }
    }

    // dependencies
    getServices () {
        return {
            model: new (require('../models/model.js'))()
        };
    }
}

exports.default = Product;
```
