# @coolgk/mvc

`npm install @coolgk/mvc`

A light javascript / typescript mvc framework that helps you to create object oriented, modulised and testable code.

[![Build Status](https://travis-ci.org/coolgk/node-mvc.svg?branch=master)](https://travis-ci.org/coolgk/node-mvc) [![Coverage Status](https://coveralls.io/repos/github/coolgk/node-mvc/badge.svg?branch=develop)](https://coveralls.io/github/coolgk/node-mvc?branch=develop) [![dependencies Status](https://david-dm.org/coolgk/node-mvc/status.svg)](https://david-dm.org/coolgk/node-mvc)


<a name="Controller"></a>

## Controller
Base controller class

**Kind**: global class  

* [Controller](#Controller)
    * [new Controller([options])](#new_Controller_new)
    * [.getRoutes()](#Controller+getRoutes) ⇒ <code>object</code>
    * [.getPermissions()](#Controller+getPermissions) ⇒ <code>object</code>
    * [.getServices()](#Controller+getServices) ⇒ <code>object</code>

<a name="new_Controller_new"></a>

### new Controller([options])

| Param | Type | Description |
| --- | --- | --- |
| [options] | <code>\*</code> | any global dependencies to pass into controllers from the entry point |

<a name="Controller+getRoutes"></a>

### controller.getRoutes() ⇒ <code>object</code>
**Kind**: instance method of [<code>Controller</code>](#Controller)  
**Returns**: <code>object</code> - - allowable routes to access controller methods. Format: { [HTTP_METHOD]: { [CLASS_METHOD_NAME]: [PARAM_PATTERN], ... } }  
<a name="Controller+getPermissions"></a>

### controller.getPermissions() ⇒ <code>object</code>
**Kind**: instance method of [<code>Controller</code>](#Controller)  
**Returns**: <code>object</code> - - a callback, which should return a boolean or Promise<boolean> value, for controlling the access of controller methods. Format: { [CLASS_METHOD_NAME]: [CALLBACK], ... }  
<a name="Controller+getServices"></a>

### controller.getServices() ⇒ <code>object</code>
**Kind**: instance method of [<code>Controller</code>](#Controller)  
**Returns**: <code>object</code> - - class dependencies which are passed into class methods as one of the arguments  
<a name="Response"></a>

## Response
setting / getting standard responses in controllers

**Kind**: global class  

* [Response](#Response)
    * [.getResponse()](#Response+getResponse) ⇒ <code>object</code>
    * [.send(data, [code])](#Response+send) ⇒ <code>object</code>
    * [.json(json, [code])](#Response+json) ⇒ <code>object</code>
    * [.text([text], code)](#Response+text) ⇒ <code>object</code>
    * [.file(path, [name], [code])](#Response+file) ⇒ <code>object</code>

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

### response.file(path, [name], [code]) ⇒ <code>object</code>
set a file download response

**Kind**: instance method of [<code>Response</code>](#Response)  
**Returns**: <code>object</code> - - set response. format: { file: { path, name }, code }  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| path | <code>string</code> |  | file path |
| [name] | <code>string</code> |  | file name, if undefined require('path').basename(path) will be used |
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
| options.url | <code>string</code> | request.originalUrl from expressjs |
| options.method | <code>string</code> | http request method GET POST etc |
| options.rootDir | <code>string</code> | rood dir of the app |
| [options.urlParser] | <code>function</code> | parser for getting url params e.g. for parsing patterns like /api/user/profile/:userId optional unless you need a more advanced parser |

<a name="Router+route"></a>

### router.route() ⇒ <code>promise</code>
this method routes urls like /moduleName/controllerName/action/param1/params2 to file modules/modulename/controllers/controllerName.js

**Kind**: instance method of [<code>Router</code>](#Router)  
**Returns**: <code>promise</code> - - returns a controller method's return value if the return value is not falsy otherwise returns standard response object genereated from the response methods called inside the controller methods e.g. response.json({...}), response.file(path, name) ...see code examples in decoupled.ts/js or full.ts/js  
