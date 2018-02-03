# @coolgk/mvc

`npm install @coolgk/mvc`

A simple, light javascript / typescript nodejs mvc framework that helps you to create object oriented, modular and testable code.

[![Build Status](https://travis-ci.org/coolgk/node-mvc.svg?branch=master)](https://travis-ci.org/coolgk/node-mvc) [![Coverage Status](https://coveralls.io/repos/github/coolgk/node-mvc/badge.svg?branch=develop)](https://coveralls.io/github/coolgk/node-mvc?branch=develop) [![dependencies Status](https://david-dm.org/coolgk/node-mvc/status.svg)](https://david-dm.org/coolgk/node-mvc) [![Known Vulnerabilities](https://snyk.io/test/github/coolgk/node-mvc/badge.svg)](https://snyk.io/test/github/coolgk/node-mvc)

## Documentation

This framework routes HTTP requests to class methods.

e.g.
**"GET /shop/product/description/1"** calls the **"description"** method in "/modules/**shop**/controllers/**product**.js" (see example code below)

In this example request, **"shop"** is a module (folder), **"product"** is a controller (file), **"description"** is an action (method) and **"1"** is a parameter. The format of the request is **/module/[controller]/[action]/[param]**

The framework looks for files from the folder structure below.

    ./index.js
    ./modules
        /shop
            /controllers
                product.js
                anothercontroller.js
            /models
                model.js
        /anothermodule
            /controllers
            ...

### Controller

The controller module must export a **"default"** property which is a class that extends the base **"Controller"** class from @coolgk/mvc/controller. Folder (module), file (controller) and method (action) names must be in lowercase without special characters except for hyphens `/[a-z\-]/` or camelCase if a request contains hyphens e.g. **action-one** is converted to **actionOne**

**product.js** controller example

```javascript
const { Controller } = require('@coolgk/mvc/controller');

class Product extends Controller {
    /**
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.params - url param values based on the patterns configured in getRoutes()
     * @param {object} dependencies.globals - the object passed into the router's constructor
     * @param {*} dependencies.services - services returned by getServices()
     */
    description ({ params, services, globals }) {
        // globals contains global dependencies passed into the router class (see example below)
        globals.response.json(
            services.model.find(params.id)
        );
    }

    /**
     * setup valid routes to methods
     */
    getRoutes () {
        return {
            GET: {
                description: ':id' // allow GET request to access the description() method
            }
        }
    }

    /**
     * setup local dependencies
     */
    getServices () {
        return {
            model: new (require('../models/model.js'))()
        };
    }

    /**
     * setup permission callbacks for accessing methods
     */
    getPermissions () {
        return {
            // * the is default permission for all methods in this class
            // this can be used for checking sessions e.g. if user has logged in
            '*': () => false, // false = deny all by default
            // true or Promise<true>: skip permission check for the description() method
            'description': () => true
        };
    }
}

exports.default = Product;
```

### Entry Point (Router)

index.js / server.js / bootstrap.js however you name it...

An example of using express with this framework

```javascript
const express = require('express');
const { Router } = require('@coolgk/mvc/router');

const app = express();

app.use(async (request, response, next) => {

    // initialise router
    const router = new Router({
        rootDir: __dirname, // required param
        url: request.originalUrl, // required param
        method: request.method, // required param
        response // you can pass anything into router, these variables are injected into controllers methods in globals
    });

    // router.route() returns the return value of the controller method if the return value is not falsy
    // otherwise it returns an object formatted by the "response" object (see the README file for @coolgk/mvc/response)
    // e.g. { code: 200, text: 'SUCCESS' }, { code: 200, json: {...} }, { code: 200, file: { name: ..., path: ... } } etc.
    const result = (await router.route());

    // for handling 404 / 403 returned from the router
    result && result.code && response.status(result.code).send(result.text);

});

app.listen(3000);
```

### Unit Test

Dependencies are injected into methods, you can easily mock them in your tests.

```javascript
'use strict';

const sinon = require('sinon');
const expect = require('chai').expect;

describe('Test Example', function () {
    // https://github.com/coolgk/node-mvc/tree/master/src/examples
    const ControllerClass = require(`../javascript/modules/example/controllers/extended`).default;

    let controller;
    let params;
    let response;
    let services;
    let globals;

    beforeEach(() => {
        // initialise controller for each test
        controller = new ControllerClass();
        // setup dependencies
        params = { id: 123 };
        // create test spy on global dependency: response
        response = {
            json: sinon.spy()
        };
        // create test stub on global dependency: services
        services = {
            model: {
                getUser: sinon.stub().returns({ name: 'abc' })
            }
        };
        // create test stub on global dependency: globals
        globals = {
            session: {
                getAll: sinon.stub().returns({ session: 'data' })
            }
        };
    });

    it('should show user name and session', async () => {
        await controller.user({ params, response, services, globals });
        expect(services.model.getUser.calledWithExactly(params.id)).to.be.true;
        expect(globals.session.getAll.calledOnce).to.be.true;
        expect(response.json.calledWithExactly({
            user: { name: 'abc' },
            session: { session: 'data' }
        })).to.be.true;
    });

});
```

### More Examples

[JavaScript Examples](https://github.com/coolgk/node-mvc/tree/master/src/examples/javascript)

- A simple app
  - [Entry Point](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/index.express.simple.js)
  - [Controller File](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/modules/example/controllers/simple.js)
- An example that decouples express from controllers
  - [Entry Point](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/index.express.decoupled.js)
  - [Controller File](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/modules/example/controllers/decoupled.js)
- An example with session and form data handlers
  - [Entry Point](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/index.express.extended.js)
  - [Controller File](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/modules/example/controllers/extended.js)
- A native node app without express
  - [Entry Point](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/index.native.js)
  - [Controller File](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/modules/example/controllers/extended.js)
- An example of using RabbitMQ for managing requests
  - [message pusher](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/index.express.rabbitmq.publisher.js)
  - [single task consumer](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/index.rabbitmq.consumer.single.task.js)
  - [catch all consumer](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/index.rabbitmq.consumer.default.js)
  - [controller](https://github.com/coolgk/node-mvc/blob/master/src/examples/javascript/modules/example/controllers/decoupled.js)

[TypeScript Examples](https://github.com/coolgk/node-mvc/tree/master/src/examples/typescript)


Report bugs here: [https://github.com/coolgk/node-mvc/issues](https://github.com/coolgk/node-mvc/issues)

<a name="Controller"></a>

## Controller
Base controller class

**Kind**: global class  

* [Controller](#Controller)
    * [.getRoutes()](#Controller+getRoutes) ⇒ <code>object</code>
    * [.getPermissions(dependencies)](#Controller+getPermissions) ⇒ <code>object</code>
    * [.getServices(dependencies)](#Controller+getServices) ⇒ <code>object</code>

<a name="Controller+getRoutes"></a>

### controller.getRoutes() ⇒ <code>object</code>
**Kind**: instance method of [<code>Controller</code>](#Controller)  
**Returns**: <code>object</code> - - routes that can access controller methods. Format: { [HTTP_METHOD]: { [CLASS_METHOD_NAME]: [PARAM_PATTERN], ... } }  
<a name="Controller+getPermissions"></a>

### controller.getPermissions(dependencies) ⇒ <code>object</code>
**Kind**: instance method of [<code>Controller</code>](#Controller)  
**Returns**: <code>object</code> - - { [CLASS_METHOD_NAME]: [CALLBACK], ... } the callback should return a boolean or Promise<boolean>  

| Param | Type | Description |
| --- | --- | --- |
| dependencies | <code>object</code> | global dependencies passed into the router's controller |

<a name="Controller+getServices"></a>

### controller.getServices(dependencies) ⇒ <code>object</code>
**Kind**: instance method of [<code>Controller</code>](#Controller)  
**Returns**: <code>object</code> - - class dependencies, which is injected into the class methods by the router  

| Param | Type | Description |
| --- | --- | --- |
| dependencies | <code>object</code> | global dependencies passed into the router's controller |

<a name="Response"></a>

## Response
setting / getting standard responses in controllers

**Kind**: global class  

* [Response](#Response)
    * [.getResponse()](#Response+getResponse) ⇒ <code>object</code>
    * [.send(data, [code])](#Response+send) ⇒ <code>object</code>
    * [.json(json, [code])](#Response+json) ⇒ <code>object</code>
    * [.text([text], code)](#Response+text) ⇒ <code>object</code>
    * [.file(path, [name], [type], [code])](#Response+file) ⇒ <code>object</code>

<a name="Response+getResponse"></a>

### response.getResponse() ⇒ <code>object</code>
**Kind**: instance method of [<code>Response</code>](#Response)  
**Returns**: <code>object</code> - - last set response. format: { code: number, json?: any, status?: string, file?: { path: string, name?: string } }  
<a name="Response+send"></a>

### response.send(data, [code]) ⇒ <code>object</code>
set arbitrary response

**Kind**: instance method of [<code>Response</code>](#Response)  
**Returns**: <code>object</code> - - set response. format: { code: number, ...data }  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| data | <code>object</code> |  | any json data |
| [code] | <code>number</code> | <code>200</code> | http status code |

<a name="Response+json"></a>

### response.json(json, [code]) ⇒ <code>object</code>
set a json response

**Kind**: instance method of [<code>Response</code>](#Response)  
**Returns**: <code>object</code> - - set response. format: { code: number, json }  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| json | <code>object</code> |  | any json data |
| [code] | <code>number</code> | <code>200</code> | http status code |

<a name="Response+text"></a>

### response.text([text], code) ⇒ <code>object</code>
set a http status response

**Kind**: instance method of [<code>Response</code>](#Response)  
**Returns**: <code>object</code> - - set response. format: { code, status }  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [text] | <code>string</code> |  | text in response |
| code | <code>number</code> | <code>200</code> | http status code |

<a name="Response+file"></a>

### response.file(path, [name], [type], [code]) ⇒ <code>object</code>
set a file download response

**Kind**: instance method of [<code>Response</code>](#Response)  
**Returns**: <code>object</code> - - set response. format: { file: { path, name }, code }  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| path | <code>string</code> |  | file path |
| [name] | <code>string</code> |  | file name, if undefined require('path').basename(path) will be used |
| [type] | <code>string</code> |  | mime type |
| [code] | <code>number</code> | <code>200</code> | http status code |

<a name="Router"></a>

## Router
**Kind**: global class  

* [Router](#Router)
    * [new Router(options)](#new_Router_new)
    * [.route()](#Router+route) ⇒ <code>promise</code>
    * [.getModuleControllerAction()](#Router+getModuleControllerAction) ⇒ <code>object</code>

<a name="new_Router_new"></a>

### new Router(options)

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> |  |
| options.url | <code>string</code> | request.url or request.originalUrl from expressjs |
| options.method | <code>string</code> | http request method GET POST etc |
| options.rootDir | <code>string</code> | rood dir of the app |
| [options.urlParser] | <code>function</code> | a callback for parsing url params e.g. /api/user/profile/:userId. default parser: @coolgk/url |

<a name="Router+route"></a>

### router.route() ⇒ <code>promise</code>
this method routes urls like /moduleName/controllerName/action/param1/params2 to file modules/modulename/controllers/controllerName.js

**Kind**: instance method of [<code>Router</code>](#Router)  
**Returns**: <code>promise</code> - - returns a controller method's return value if the return value is not falsy otherwise returns standard response object genereated from the response methods called inside the controller methods e.g. response.json({...}), response.file(path, name) ...see code examples in decoupled.ts/js or full.ts/js  
<a name="Router+getModuleControllerAction"></a>

### router.getModuleControllerAction() ⇒ <code>object</code>
**Kind**: instance method of [<code>Router</code>](#Router)  
**Returns**: <code>object</code> - - {module, controller, action, originalModule, originalController, originalAction} originals are values before they are santised and transformed e.g. /module.../ConTroller/action-one -> {action: 'module', controller: 'controller', action: 'actionOne', originalModule: 'module...', controller: 'ConTroller', action: 'action-one' }  
