'use strict';

const sinon = require('sinon');
const expect = require('chai').expect;

describe('Test Example', function () {

    const ControllerClass = require(`../javascript/modules/example/controllers/extended`).default;

    let controller;
    let params;
    let response;
    let services;
    let globals;

    beforeEach(() => {
        controller = new ControllerClass(); // initialise controller for each test

        params = {}; // setup dependencies

        response = { // create test spy on global dependency: response
            json: sinon.spy()
        };

        services = {
            model: { // create test stub on global dependency: services
                getUser: sinon.stub().returns({ name: 'abc' })
            }
        };

        globals = {
            session: { // create test stub on global dependency: globals
                getAll: sinon.stub().returns({ session: 'data' })
            }
        };
    });

    it('should should user details', async () => {
        params.id = 123;

        await controller.user({ params, response, services, globals });

        expect(services.model.getUser.calledWithExactly(params.id)).to.be.true;

        expect(globals.session.getAll.calledOnce).to.be.true;

        expect(response.json.calledWithExactly({
            user: { name: 'abc' },
            session: { session: 'data' }
        })).to.be.true;
    });

});
