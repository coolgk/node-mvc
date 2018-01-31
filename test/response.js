'use strict';

// const sinon = require('sinon');
const chai = require('chai');
// chai.use(require("chai-as-promised"));
const expect = chai.expect;

// const config = require('../test.config.js');

describe('Response Module', function () {

    const { Response, ResponseError } = require(`../dist/response`);

    let response;

    // before(() => {});
    beforeEach(() => {
        response = new Response();
    });
    // afterEach(() => {});
    // after(() => {});

    it('should set responses', () => {
        const data = {a: 1, b: 2};
        response.send(data, 201);
        expect(response.getResponse()).to.deep.equal({ ...data, code: 201 });

        response.send(data);
        expect(response.getResponse()).to.deep.equal({ ...data, code: 200 });

        response.json(data, 202);
        expect(response.getResponse()).to.deep.equal({ json: data, code: 202 });

        response.json(data);
        expect(response.getResponse()).to.deep.equal({ json: data, code: 200 });

        response.text('message', 203);
        expect(response.getResponse()).to.deep.equal({ text: 'message', code: 203 });

        response.text('message');
        expect(response.getResponse()).to.deep.equal({ text: 'message', code: 200 });

        let file = {
            path: Math.random(),
            name: Math.random(),
            type: undefined
        };
        response.file(file.path, file.name);
        expect(response.getResponse()).to.deep.equal({ file, code: 200 });

        file.name = `${Math.random()}.txt`;
        file.path = `abc/${Math.random()}/${file.name}`;
        response.file(file.path, undefined, undefined, 201);
        expect(response.getResponse()).to.deep.equal({ file: { ...file, name: undefined }, code: 201 });

        response.file(undefined, file.name);
        expect(response.getResponse()).to.deep.equal({ text: ResponseError.File_Not_Found, code: 404 });

        response.file(file.path, undefined, 'text/html', 201);
        expect(response.getResponse()).to.deep.equal({ file: { ...file, type: 'text/html', name: undefined }, code: 201 });
    });

    it('response should return an object when no response is set', () => {
        expect(response.getResponse()).to.deep.equal({});
    })
});
