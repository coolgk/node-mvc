/**
 * an extended example of using the @coolgk/mvc framework with session and form data handlers
 */
import { createClient } from 'redis';

import { Router } from '@coolgk/mvc/router';

import { formData } from '@coolgk/formdata';
import { Session } from '@coolgk/session';

// import app configurations
import { config } from './config';

import { createServer } from 'http';
import { lookup } from 'mime-types';
import { createReadStream, stat } from 'fs';
import { basename } from 'path';

createServer(async (request, response) => {
    // initilaise session
    // see @coolgk/session https://www.npmjs.com/package/@coolgk/session
    const session = new Session({
        redisClient: createClient(config.redis),
        secret: config.secret,
        expiry: config.sessionMaxLife,
        request,
        response,
        cookie: {
            httpOnly: true,
            secure: config.secureCookie
        }
    });

    // setup router
    const router = new Router({
        rootDir: __dirname, // required param
        url: request.url || '', // required param
        method: request.method || 'GET', // required param
        // setup form data handler for 'application/json', 'application/x-www-form-urlencoded' and 'multipart/form-data'
        // see @coolgk/formdata https://www.npmjs.com/package/@coolgk/formdata
        formdata: formData(request, { dir: config.uploadDir }), // pass formdata in as global a dependency
        // pass session in as global a dependency
        session,
        config, // pass app config in as global a dependency
        ip: request.connection.remoteAddress // pass ip address into router (controller methods)
    });

    // router.route() returns the return value of the controller method if the return value is not falsy
    // otherwise it returns an object from formatted by the "response" object (see the README file for @coolgk/mvc/response)
    // e.g. { code: 200, text: 'SUCCESS' }, { code: 200, json: {...} }, { code: 200, file: { name: ..., path: ... } } etc.
    // this example uses the injected response object for setting up http responese in a standard format
    const result = (await router.route());

    // handle json, file or text responses
    for (const type of ['json', 'file', 'text']) {
        if (result[type]) {
            switch (type) {
                case 'json':
                    response.writeHead(result.code || 200, { 'Content-Type': 'application/json' });
                    response.end(
                        JSON.stringify(result[type])
                    );
                    break;
                case 'text':
                    response.writeHead(result.code || 200, { 'Content-Type': 'text/html; charset=utf8' });
                    response.end(result.text);
                    break;
                case 'file':
                    const file = result[type] || { name: '', path: '', type: '' };
                    stat(file.path, (error, stats) => {
                        if (error) {
                            response.writeHead(404, {'Content-Type': 'text/html; charset=utf8'});
                            response.end('File Not Found');
                        } else {
                            if (!file.name || String(file.name).trim() === '') {
                                file.name = basename(file.path);
                            }
                            response.writeHead(200, {
                                'Content-Type': file.type || lookup(file.name) || 'application/octet-stream',
                                'Content-Length': stats.size
                            });
                            createReadStream(file.path).pipe(response);
                        }
                    });
                    break;
            }
            return;
        }
    }

    // json, file and text are the only valid responses from this simple app
    // log error for anything else
    // your custom error logger
    console.error(result); // tslint:disable-line
    response.writeHead(500, { 'Content-Type': 'text/html; charset=utf8' });
    response.end('Internal Server Error');

}).listen(3000);

process.on('unhandledRejection', (error) => {
    // your custom error logger
    console.error(error); // tslint:disable-line
});
