'use strict';

const lti = require('../');
const should = require('should');

describe('LTI', function() {
  before(function() {
    this.lti = lti;
  });

  describe('.Provider', function() {
    it('should exist', function() {
      should.exist(this.lti.Provider);
    });

    it('should be an instance of Provider', function() {
      this.lti.Provider.should.be.an.instanceOf(Object);
      this.lti.Provider.should.equal(require('../src/provider'));
    });
  });

  describe('.Consumer', function() {
    it('should exist', function() {
      should.exist(this.lti.Consumer);
    });

    it('should be an instance of Consumer', function() {
      this.lti.Consumer.should.be.an.instanceOf(Object);
      this.lti.Consumer.should.equal(require('../src/consumer'));
    });
  });

  describe('.Stores', function() {
    it('should not be empty', function() {
      should.exist(this.lti.Stores);
    });

    it('should include NonceStore', function() {
      should.exist(this.lti.Stores.NonceStore);
    });
  });
});
