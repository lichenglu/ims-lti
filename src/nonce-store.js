'use strict';

const noop = () => undefined;

class NonceStore {
  /**
   * @todo removed bound methods
   */
  constructor() {
    this.isNew = this.isNew.bind(this);
    this.setUsed = this.setUsed.bind(this);
  }

  isNonceStore() {
    return true;
  }

  isNew(nonce, timestamp, next = noop) {
    next(new Error('NOT IMPLEMENTED'), false);
  }

  setUsed(nonce, timestamp, next = noop) {
    next(new Error('NOT IMPLEMENTED'));
  }
}

module.exports = NonceStore;
