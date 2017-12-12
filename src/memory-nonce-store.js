'use strict';

/*
 * Decaffeinate suggestions:
 * DS001: Remove Babel/TypeScript constructor workaround
 * DS102: Remove unnecessary code created because of implicit returns
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const NonceStore = require('./nonce-store');

// Five minutes
const EXPIRE_IN_SEC = 5 * 60;

const noop = () => undefined;

class MemoryNonceStore extends NonceStore {
  static isStale(timestamp, currentTime = Math.round(Date.now() / 1000)) {
    const parsedTimestamp = parseInt(timestamp, 10);
    const timeStampAge = currentTime - parsedTimestamp;

    return isNaN(timeStampAge) || timeStampAge > EXPIRE_IN_SEC;
  }

  constructor() {
    super();

    this.used = Object.create(null);
  }

  isNew(nonce, timestamp, next = noop) {
    if (nonce == null || timestamp == null || typeof nonce === 'function') {
      return next(new Error('Invalid parameters'), false);
    }

    if (this._hasNonces(nonce)) {
      return next(new Error('Nonce already seen'), false);
    }

    if (MemoryNonceStore.isStale(timestamp)) {
      return next(new Error('Invalid or expired timestamp'), false);
    }

    return this.setUsed(nonce, timestamp, err => next(err, err == null));
  }

  /**
   * Store nonce.
   *
   * @param {string} nonce Nonce to store
   * @param {number} timestamp Nonce's timestamp
   * @param {function(e: Error): void} [next] Called with the result
   * @todo `MemoryNonceStore#setUsed` should validate parameters.
   */
  setUsed(nonce, timestamp, next = noop) {
    this.used[nonce] = timestamp + EXPIRE_IN_SEC;
    next(null);
  }

  _hasNonces(nonce) {
    this._clearNonces();

    return this.used[nonce] !== undefined;
  }

  _clearNonces() {
    const now = Math.round(Date.now() / 1000);

    /* eslint-disable guard-for-in */
    for (const nonce in this.used) {
      const expiry = this.used[nonce];

      if (expiry <= now) {
        delete this.used[nonce];
      }
    }
    /* eslint-enable guard-for-in */
  }
}

module.exports = MemoryNonceStore;
