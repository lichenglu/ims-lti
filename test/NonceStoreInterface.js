'use strict';

const NonceStore = require('../src/nonce-store');
const should = require('should');

describe('NonceStore [Interface Class]', function() {
  before(function() {
    this.store = new NonceStore('consumer_key');
  });

  // Standard nonce tests
  //
  // -- do not change below this line--

  describe('NonceStore', function() {
    it('should have extend NonceStore', function() {
      should.exist(this.store.isNonceStore);
      this.store.isNonceStore().should.be.ok();
    });
  });

  describe('.isNew', () => {
    it('should exist', function() {
      should.exist(this.store.isNew);
    });

    it('should return Not Implemented', function(done) {
      this.store.isNew(undefined, undefined, function(err, valid) {
        err.should.not.equal(null);
        err.message.should.match(/NOT/i);
        valid.should.equal(false);
        done();
      });
    });
  });

  return describe('.setUsed', function() {
    it('should exist', function() {
      should.exist(this.store.setUsed);
    });

    it('should return Not Implemented', function(done) {
      this.store.setUsed(undefined, undefined, function(err) {
        err.should.not.equal(null);
        err.message.should.match(/NOT/i);
        done();
      });
    });
  });
});
