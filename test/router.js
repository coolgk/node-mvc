'use strict';

// const sinon = require('sinon');
const chai = require('chai');
// chai.use(require("chai-as-promised"));
const expect = chai.expect;

// const config = require('../test.config.js');

describe('Router Module', function () {

    const { Router } = require(`../dist/router`);
    const mkdirp = require('mkdirp-promise');
    const fs = require('fs');
    const del = require('del');

    let router;
    let options;
    const rootDir = '/tmp/router-test' + (1000000 * Math.random()).toFixed(0);
    const module = 'module' + (1000000 * Math.random()).toFixed(0);
    const controller = 'controller' + (1000000 * Math.random()).toFixed(0);
    const action = 'action' + (1000000 * Math.random()).toFixed(0);
    const controllerDir = `${rootDir}/modules/${module}/controllers`;
    const controllerFile = `${controllerDir}/${controller}.js`;

    before((done) => {
        options = {
            url: `/${module}/${controller}/${action}/param1?query=value&x=y`,
            method: 'GET',
            rootDir: rootDir
        };
        router = new Router(options);

        mkdirp(controllerDir).then(() => {
            fs.writeFile(controllerFile, getCode(), 'utf8', (error) => {
                if (error) return done(data);
                done();
            });
        });
    });

    // beforeEach(() => {});
    // afterEach(() => {});

    after(() => {
        return del(rootDir, {force: true});
    });

    it('should get action module controller from url', () => {
        expect(router.getModuleControllerAction()).to.deep.equal({ action, module, controller });
    });

    it('should call correct methods from url', () => {
        router.route();
    });

    it('should allow and deny methods based on getRoutes()');

    it('should allow and deny methods based on getPermissions()');

    it('should pass all options to controllers constructor');

    it('should pass params, services, response to methods');

    function getCode () {
        return `
const { Controller } from '${__dirname + '/../dist/controller'}';

export class Simple extends Controller {

    getRoutes () {
        return {
            GET: {
                index: '',
                ${action}: ':id'
            }
        };
    }

    getPermissions () {
        return {
            '*': () => false
            ${action}: () => Promise.resolve(true)
        };
    }

    index () {

    }

    ${action} () {
        return '${action}';
    }
}

export default Simple;
        `;
    }
});

