'use strict';

// const sinon = require('sinon');
const chai = require('chai');
// chai.use(require("chai-as-promised"));
const expect = chai.expect;

// const config = require('../test.config.js');

describe('Response Module', function () {

    const { Response, IResponseError } = require(`../dist/response`);

    let response;

    before(() => {
        response = new Response();
    });

    // beforeEach(() => {});
    // afterEach(() => {});
    // after(() => {});

    it('should have all base methods', () => {
        // expect(controller).to.have.property('getRoutes').and.to.be.a('function');
        // expect(controller).to.have.property('getPermissions').and.to.be.a('function');
        // expect(controller).to.have.property('getServices').and.to.be.a('function');
        const data = {a: 1, b: 2};
        response.send(data, 201);
        expect(response.getResponse()).to.deep.equal({ ...data, code: 201 });

        response.json(data, 202);
        expect(response.getResponse()).to.deep.equal({ json: data, code: 202 });

        response.status(203, 'message');
        expect(response.getResponse()).to.deep.equal({ status: 'message', code: 203 });

        const file = {
            path: Math.random(),
            name: Math.random()
        };
        response.file(file.path, file.name);
        expect(response.getResponse()).to.deep.equal({ file, code: 200 });

        response.file(undefined, file.name);
        expect(response.getResponse()).to.deep.equal({ status: IResponseError.File_Not_Found, code: 404 });
    });

});
