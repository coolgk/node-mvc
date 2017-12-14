import { config } from './config';

import * as express from 'express';
import * as helmet from 'helmet';
import * as cors from 'cors';
import * as bodyParser from 'body-parser';
import * as cookieParser from 'cookie-parser';
import * as multer from 'multer';
// import * as Router from './router';

const app = express();

app.use((request, response, next) => {
    app.locals.response = response;
    next();
});

app.use(helmet()); // http://expressjs.com/en/advanced/best-practice-security.html
app.use(
    cors({
        origin: config.cors || '*',
        credentials: true
    })
);

// ============= SET UP POST VARIABLES
// app.use(bodyParser.json()); // for parsing application/json
// app.use(bodyParser.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded

// ============= SETUP COOKIE
app.set('trust proxy', 1); // trust first proxy
app.use(cookieParser(config.secret));



import { createWriteStream } from 'fs';
import * as Busboy from 'busboy';
import { toArray } from '@coolgk/utils/array';
import { generateFile } from '@coolgk/utils/tmp';

// ============= SETUP ROUTER
app.use((request, response, next) => {
    // ============= SETUP UPLOADED FILES

    const files = {
        get: (names: string | string[], folder: string): Promise<{}> => {
            const busboy = new Busboy({ headers: request.headers });

            return new Promise((resolve) => {
                const uploadedFiles = {};
                busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
                    console.log(1111, filename);
                    if (toArray(names).includes(fieldname)) {
                        if (!uploadedFiles[fieldname]) {
                            uploadedFiles[fieldname] = [];
                        }
                        generateFile({dir: folder, postfix: '', keep: true}).then(({ path }) => {
                            

                            let filesize = 0;
                            const writeableStream = createWriteStream(path);
                            file.on('data', (data) => {
                                filesize += data.length;
                                writeableStream.write(data);
                            });
                            file.on('end', () => {
                                writeableStream.end();
                                uploadedFiles[fieldname].push({
                                    name: filename,
                                    encoding,
                                    mimetype,
                                    size: filesize,
                                    path: path
                                });
                            });
                            
                        });
                    }
                });
                
                busboy.on('finish', () => {
                    resolve(uploadedFiles);
                    console.log(uploadedFiles);
                    // console.log(post);
                });

                request.pipe(busboy);
            });

        }
    };

    const contentType = request.get('content-type');
    if (contentType == 'application/x-www-form-urlencoded' || contentType.indexOf('multipart/form-data') === 0) {
        const busboy = new Busboy({ headers: request.headers });

/*
        const uploadedFiles = {};
        busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
            if (!uploadedFiles[fieldname]) {
                uploadedFiles[fieldname] = [];
            }

            const filepath = '/tmp/hhh';
            let filesize = 0;
            const writeableStream = createWriteStream(filepath);
            file.on('data', (data) => {
                filesize += data.length;
                writeableStream.write(data);
            });
            file.on('end', () => {
                writeableStream.end();

                uploadedFiles[fieldname].push({
                    name: filename,
                    encoding,
                    mimetype,
                    size: filesize
                    path: filepath
                });
            });
        });
*/

        busboy.on('file', (fieldname, file) => {
            file.resume()
        });

        const post = {};
        busboy.on('field', (fieldname, value, fieldnameTruncated, valTruncated, encoding, mimetype) => {
            if (post[fieldname]) {
                if (post[fieldname] instanceof Array) {
                    post[fieldname].push(value);
                } else {
                    post[fieldname] = [
                        post[fieldname], value
                    ];
                }
            } else {
                post[fieldname] = value;
            }
        });

        busboy.on('finish', () => {
            // console.log(uploadedFiles);

            // for (let file of uploadedFiles.test) {
                // file.move('/tmp/rrr')
            // }

            console.log(post);
        });

        request.pipe(busboy);

    }
    
    
    setTimeout(async () => {
        const f = await files.get('test', '/tmp');
        console.log(f);
        
    }, 100)
    
    // const files = new Proxy(
        // multer({dest: config.tmpFolder}),
        // {
            // get: (target: any, property: string) => {
                // return new Promise((resolve, reject) => {
                    // target.array(property, 50)(
                        // request,
                        // response,
                        // (error) => error ? reject(error) : resolve(request.files)
                    // );
                // });
            // }
        // }
    // );


    response.json([]);

    // (new Router({
        // url: request.originalUrl,
        // method: request.method,
        // session: new Session({
            // redisClient: require('redis').createClient(config.redis),
            // secret: config.secret,
            // expiry: config.sessionMaxLife,
            // token: response.locals.cookie.get('accessToken') || (request.header('authorization') || '').replace(/^Bearer /, ''),
            // ip: request.ip,
            // cookie: {
                // set: (name: string, value: string): void => {
                    // response.cookie(name, value, {
                        // httpOnly: true,
                        // signed: true,
                        // secure: config.secureCookie,
                        // options.maxAge: config.sessionMaxLife || 0
                    // });
                // },
                // clear (): void {
                    // response.clearCookie(name);
                // }
            // }
        // })
    // })).route();

});

// ============= UNHANDLED REJECTIONS FROM PROMISE
process.on('unhandledRejection', (error) => {
    console.error(error);
    app.locals.response.headersSent || app.locals.response.sendStatus(500);
});

// ============= GLOBAL ERROR HANDLER (THIS DOES NOT CATCH UNHANDLED REJECTIONS)
// next is an unused variable but required for this callback
app.use((error, request, response, next) => { // eslint-disable-line no-unused-vars
    console.error(error);
    response.sendStatus(500);
});

// ============= START SERVER
const server = app.listen(config.port, config.host);
server.timeout = config.serverTimeout;
