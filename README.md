# @coolgk/${name}

A light javascript / typescript mvc framework that helps you to organise your code

testable, OO

`npm install @coolgk/mvc`


[![Build Status](https://travis-ci.org/coolgk/utils.svg?branch=master)](https://travis-ci.org/coolgk/utils)
[![Coverage Status](https://coveralls.io/repos/github/coolgk/utils/badge.svg?branch=develop)](https://coveralls.io/github/coolgk/utils?branch=develop)
[![dependencies Status](https://david-dm.org/coolgk/utils/status.svg)](https://david-dm.org/coolgk/utils)





<a name="Controller"></a>

## Controller
**Kind**: global class  
**Export**:   

* [Controller](#Controller)
    * [new Controller()](#new_Controller_new)
    * _instance_
        * [.getRoutes()](#Controller+getRoutes) ⇒ <code>object</code>
        * [.getPermissions()](#Controller+getPermissions) ⇒ <code>object</code>
        * [.getServices()](#Controller+getServices) ⇒ <code>object</code>
    * _static_
        * [.Controller](#Controller.Controller)
            * [new Controller(options)](#new_Controller.Controller_new)

<a name="new_Controller_new"></a>

### new Controller()
Base controller class

<a name="Controller+getRoutes"></a>

### controller.getRoutes() ⇒ <code>object</code>
**Kind**: instance method of [<code>Controller</code>](#Controller)  
**Returns**: <code>object</code> - - allowable routes to access controller methods. Format: { [HTTP_METHOD]: { [CLASS_METHOD_NAME]: [PARAM_PATTERN], ... } }  
<a name="Controller+getPermissions"></a>

### controller.getPermissions() ⇒ <code>object</code>
**Kind**: instance method of [<code>Controller</code>](#Controller)  
**Returns**: <code>object</code> - - permission callback, which should return a boolean or Promise<boolean> value, for accessing controller methods. Format: { [CLASS_METHOD_NAME]: [CALLBACK], ... }  
<a name="Controller+getServices"></a>

### controller.getServices() ⇒ <code>object</code>
**Kind**: instance method of [<code>Controller</code>](#Controller)  
**Returns**: <code>object</code> - - class dependencies which are passed into class methods as one of the arguments  
<a name="Controller.Controller"></a>

### Controller.Controller
**Kind**: static class of [<code>Controller</code>](#Controller)  
<a name="new_Controller.Controller_new"></a>

#### new Controller(options)
Creates an instance of Controller.


| Param | Type | Description |
| --- | --- | --- |
| options | <code>\*</code> | any global dependencies to pass into controllers from the entry point |

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
| options.url | <code>string</code> | request.originalUrl from expressjs |
| options.method | <code>string</code> | http request method GET POST etc |
| options.rootDir | <code>string</code> | rood dir of the app |
| [options.urlParser] | <code>function</code> | parser for getting url params e.g. for parsing patterns like /api/user/profile/:userId optional unless you need a more advanced parser |

<a name="Router+route"></a>

### router.route() ⇒ <code>promise</code>
this method routes urls like /moduleName/controllerName/action/param1/params2 to file modules/modulename/controllers/controllerName.js

**Kind**: instance method of [<code>Router</code>](#Router)  
**Returns**: <code>promise</code> - - returns a controller method's return value if the return value is not falsy otherwise returns standard response object genereated from the response methods called inside the controller methods e.g. response.json({...}), response.file(path, name) ...see code examples in decoupled.ts/js or full.ts/js  
