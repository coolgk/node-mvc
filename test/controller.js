'use strict';

// const sinon = require('sinon');
const chai = require('chai');
// chai.use(require("chai-as-promised"));
const expect = chai.expect;

// const config = require('../test.config.js');

describe('Controller Module', function () {

    const { Controller } = require(`../dist/controller`);

    let controller;
    let options;

    before(() => {
        options = {
            any: '123',
            thing: 'thing'
        };
        controller = new Controller(options);
    });

    // beforeEach(() => {});
    // afterEach(() => {});
    // after(() => {});

    it('should have all base methods', () => {
        // expect(controller).to.have.property('getRoutes').and.to.be.a('function');
        // expect(controller).to.have.property('getPermissions').and.to.be.a('function');
        // expect(controller).to.have.property('getServices').and.to.be.a('function');
        expect(controller.getRoutes()).to.deep.equal({});
        expect(controller.getPermissions()).to.deep.equal({});
        expect(controller.getServices()).to.deep.equal({});
    });

});
