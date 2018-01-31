# @coolgk/mvc

`npm install @coolgk/mvc`

A light javascript / typescript mvc framework that helps you to create object oriented, modulised and testable code.

[![Build Status](https://travis-ci.org/coolgk/node-mvc.svg?branch=master)](https://travis-ci.org/coolgk/node-mvc) [![Coverage Status](https://coveralls.io/repos/github/coolgk/node-mvc/badge.svg?branch=develop)](https://coveralls.io/github/coolgk/node-mvc?branch=develop) [![dependencies Status](https://david-dm.org/coolgk/node-mvc/status.svg)](https://david-dm.org/coolgk/node-mvc) [![Known Vulnerabilities](https://snyk.io/test/github/coolgk/node-mvc/badge.svg)](https://snyk.io/test/github/coolgk/node-mvc)

## How this works

This framework routes HTTP requests to class methods.

e.g.
**"GET /shop/product/description/1"** calls the **"description"** method in **"/modules/api/controllers/product.js"** (see example code below)

In this example request, **"shop"** is a module (folder), **"product"** is a controller (file), **"description"** is an action (method) and **"1"** is a parameter i.e. the format of the request is **/module/[controller]/[action]/[param]**

The framework looks for the file from the folder structure below:

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

**product.js** i.e. the controller file must export a **default** property which is a class that extends the base **Controller** class from @coolgk/mvc/controller

```javascript
const { Controller } = require('@coolgk/mvc/controller');

class Product extends Controller {
    /**
     * @param {object} dependencies - this param is destructured in this example
     * @param {object} dependencies.params - url param values based on the patterns configured in getRoutes()
     * @param {*} dependencies.services - services from returned from getServices()
     */
    description ({ params, services }) {
        // this._options contains global dependencies passed into the router class (see example below)
        this._options.express.response.json(
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
}

exports.default = Product;
```


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
