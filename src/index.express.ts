
const app = require('express')();
const config = require('./config.js');

app.use(require('helmet')()); // http://expressjs.com/en/advanced/best-practice-security.html

app.use(
    require('cors')({
        origin: config.client.domains || false,
        credentials: true
    })
);

// ============= SET UP POST VARIABLES
let bodyParser = require('body-parser');
app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({extended: true})); // for parsing application/x-www-form-urlencoded

// ============= SETUP UPLOADED FILES
let multer = require('multer'); // for parsing multipart/form-data
let upload = multer({dest: config.tmpDir});
app.use(upload.any());

// ============= SETUP COOKIE
app.set('trust proxy', 1); // trust first proxy
app.use(require('cookie-parser')(config.secret));

// ============= UNHANDLED REJECTIONS FROM PROMISE
process.on('unhandledRejection', (error) => {
    // if response is already sent in code, this will cause "header already sent" error
    app.locals.response.status(500).send('internal error');
});

// ============= SETUP ROUTER
app.use((request, response, next) => {
    let Router = require('./lib/router.js');
    let appRouter = new Router({
        method: request.method,
        get: request.query,
        post: request.body,
        files: request.files || [],
        ip: request.ip,
        debugInfo: response.locals.errorLogger.getDebugInfo(),
        // example token in header - authorization: 'Bearer eyJleHAiOjE0OTM5MTk1MjAzODIsImlhdCI6MTQ5...'
        accessToken: response.locals.cookie.get('accessToken') || (request.header('authorization') || '').replace(/^Bearer /, ''),
        csrfToken: request.header('X-XSRF-TOKEN'),
        response,
        next
    });
    appRouter.route(request.originalUrl);

    const session = ;

    (new Router({
        url: request.originalUrl,
        method: request.method,
        session: new Session({
            redisClient: require('redis').createClient(config.redis),
            secret: config.secret,
            expiry: config.sessionMaxLife,
            token: response.locals.cookie.get('accessToken') || (request.header('authorization') || '').replace(/^Bearer /, ''),
            ip: request.ip,
            cookie: {
                set: (name: string, value: string): void => {
                    response.cookie(name, value, {
                        httpOnly: true,
                        signed: true,
                        secure: config.secureCookie,
                        options.maxAge: config.sessionMaxLife || 0
                    });
                },
                clear (): void {
                    response.clearCookie(name);
                }
            }
        })
    })).route();

});

// ============= GLOBAL ERROR HANDLER (THIS DOES NOT CATCH UNHANDLED REJECTIONS)
// next is an unused variable but required for this callback
app.use((error, request, response, next) => { // eslint-disable-line no-unused-vars
    response.status(500).send('internal error');
});

// ============= START SERVER
const server = app.listen(config.port, config.host);
server.timeout = config.serverTimeout;
