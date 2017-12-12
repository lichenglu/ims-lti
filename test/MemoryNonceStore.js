'use strict';

require('should');

const MemoryNonceStore = require('../src/memory-nonce-store');
const shared = require('./shared');

describe('MemoryNonceStore', function() {
  shared.shouldBehaveLikeNonce(() => new MemoryNonceStore());
});
