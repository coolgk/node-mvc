'use strict';

// const sinon = require('sinon');
const chai = require('chai');
chai.use(require("chai-as-promised"));
const expect = chai.expect;

// const config = require('../test.config.js');

describe('Router Module', function () {

    const { Router, RouterError } = require(`../dist/router`);
    const mkdirp = require('mkdirp-promise');
    const fs = require('fs');
    const del = require('del');
    const os = require('os');

    let router;
    const rootDir = `${os.tmpdir()}/router_test_${(1000000 * Math.random()).toFixed(0)}`;
    const module = 'module' + (1000000 * Math.random()).toFixed(0);
    const controller = 'controller' + (1000000 * Math.random()).toFixed(0);
    const action = 'action' + (1000000 * Math.random()).toFixed(0);
    const controllerDir = `${rootDir}/modules/${module}/controllers`;
    const controllerFile = `${controllerDir}/${controller}.js`;

    before((done) => {
        mkdirp(controllerDir).then(() => {
            Promise.all([
                new Promise((resolve) => {
                    fs.writeFile(controllerFile, getCode(), 'utf8', (error) => {
                        if (error) return done(data);
                        resolve();
                    });
                }),
                new Promise((resolve) => {
                    fs.writeFile(`${controllerDir}/${controller}noglobalpermission.js`, getCode(true), 'utf8', (error) => {
                        if (error) return done(data);
                        resolve();
                    });
                })
            ]).then(() => done());
        });
    });

    beforeEach(() => {
        router = new Router({
            url: `/${module}/${controller}/${action}/param1?query=value&x=y`,
            method: 'GET',
            rootDir: rootDir
        });
    });
    // afterEach(() => {});

    after(() => {
        return del(rootDir, {force: true});
    });

    it('should get action module controller from url', () => {
        expect(router.getModuleControllerAction()).to.deep.equal({
            action,
            module,
            controller,
            originalAction: action,
            originalModule: module,
            originalController: controller
        });
    });

    it('should call correct methods from url', () => {
        return expect(router.route()).to.eventually.deep.equal({ json: {a: 7}, code: 200 });
    });

    it('should allow and deny methods based on getRoutes()', () => {
        const router2 = new Router({
            url: `/${module}/${controller}`,
            method: 'GET',
            rootDir: rootDir
        });

        const router3 = new Router({
            url: `/${module}/${controller}`,
            method: 'POST',
            rootDir: rootDir
        });

        return Promise.all([
            expect(router2.route()).to.eventually.equal(undefined),
            expect(router3.route()).to.eventually.deep.equal({ code: 404, text: RouterError.Not_Found_404 }),
        ]);
    });

    it('should allow and deny methods based on getPermissions()', () => {
        const router = new Router({
            url: `/${module}/${controller}/no-access`,
            method: 'GET',
            rootDir: rootDir
        });

        // should hit global permission '*'
        const router2 = new Router({
            url: `/${module}/${controller}/global-permission`,
            method: 'GET',
            rootDir: rootDir
        });

        // should hit default permission when '*' is not set
        const router3 = new Router({
            url: `/${module}/${controller}noglobalpermission/global-permission`,
            method: 'GET',
            rootDir: rootDir
        });

        return Promise.all([
            expect(router.route()).to.eventually.deep.equal({ code: 403, text: RouterError.Forbidden_403 }),
            expect(router2.route()).to.eventually.deep.equal({ code: 403, text: RouterError.Forbidden_403 }),
            expect(router3.route()).to.eventually.equal(undefined)
        ]);
    });

    it('should pass params, services, response to methods', () => {
        const router = new Router({
            url: `/${module}/${controller}/with-params/12345/2017-01-29`,
            method: 'POST',
            rootDir: rootDir
        });
        return expect(router.route()).to.eventually.deep.equal({
            code: 200,
            json: {
                services: { a: 1 },
                params: {
                    id: '12345',
                    date: '2017-01-29'
                }
            }
        });
    });

    it('should return the return value of the controller method if the return value is not undefined', () => {
        const router = new Router({
            url: `/${module}/${controller}/with-return-value`,
            method: 'POST',
            rootDir: rootDir
        });
        return expect(router.route()).to.eventually.equal(action);
    });

    it('should show 404 if controller file does not exist', () => {
        const router = new Router({
            url: `/${module}/notThere`,
            method: 'GET',
            rootDir: rootDir
        });
        return expect(router.route()).to.eventually.deep.equal({ code: 404, text: RouterError.Not_Found_404 });
    });

    it('should hit default module controller view if url is empty', () => {
        const router = new Router({
            url: `?a=b`,
            method: 'GET',
            rootDir: rootDir
        });

        expect(router.getModuleControllerAction()).to.deep.equal({
            action: 'index',
            module: 'index',
            controller: 'index',
            originalAction: undefined,
            originalModule: undefined,
            originalController: undefined
        });

        return expect(router.route()).to.eventually.deep.equal({ code: 404, text: RouterError.Not_Found_404 });
    });

    // it('camelCase url should hit method');

    function getCode (noGlobalPermission) {
        return `
const { Controller } = require('${__dirname + '/../dist/controller'}');

class Simple extends Controller {

    getRoutes () {
        return {
            GET: {
                index: '',
                ${action}: '',
                noAccess: '',
                'globalPermission': ''
            },
            POST: {
                withReturnValue: '',
                withParams: ':id/:date'
            }
        };
    }

    getPermissions () {
        return {
            ${noGlobalPermission ? '' : "'*': () => false,"}
            ${action}: () => Promise.resolve(true),
            withReturnValue: () => true,
            noAccess: () => false,
            index: () => true,
            withParams: () => Promise.resolve(true)
        };
    }

    getServices () {
        return {
            a: 1
        };
    }

    index () {

    }

    globalPermission () {

    }

    ${action} ({response}) {
        response.json({a: 7});
    }

    noAccess () {}

    withReturnValue () {
        return '${action}';
    }

    withParams ({services, params, response}) {
        response.json({services, params});
    }
}

module.exports = {
    default: Simple,
    Simple
};
        `;
    }
});
