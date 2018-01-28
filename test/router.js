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
    const rootDir = '/tmp/router-test' + Math.random();
    const module = 'module' + Math.random();
    const controller = 'controller' + Math.random();
    const action = 'action' + Math.random();
    const controllerDir = `${rootDir}/modules/${module}/controllers`;

    before(() => {
        options = {
            url: `${module}/${controller}/${action}/param1?query=value&x=y`,
            method: 'GET',
            rootDir: rootDir
        };
        router = new Router(options);
        return mkdirp(controllerDir);
    });

    // beforeEach(() => {});
    // afterEach(() => {});

    after(() => {
        return del(rootDir, {force: true});
    });

    it('should have all base methods', () => {


        expect(router.getModuleControllerAction()).to.deep.equal({action: 'action1', module: 'module1', controller: 'controller1'});


    });

});
