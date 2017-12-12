'use strict';

const NonceStore = require('./nonce-store');

const noop = () => undefined;
const isString = v => typeof v === 'string';

// Five minutes
const EXPIRE_IN_SEC = 5 * 60;

class RedisNonceStore extends NonceStore {
  static isStale(timestamp, currentTime = Math.round(Date.now() / 1000)) {
    const parsedTimestamp = parseInt(timestamp, 10);
    const timeStampAge = currentTime - parsedTimestamp;

    return isNaN(timeStampAge) || timeStampAge > EXPIRE_IN_SEC;
  }

  /**
   * Creates an instance of RedisNonceStore.
   *
   * @param {string|object} consumerKeyOrClient Redis client or deprecated consumer key
   * @param {object} [client] Redis client
   * @deprecated consumer key argument is deprecated and ignored
   */
  constructor(consumerKeyOrClient, client) {
    super();

    this.redis =
      isString(consumerKeyOrClient) && client != null
        ? client
        : consumerKeyOrClient;
  }

  isNew(nonce, timestamp, next = noop) {
    if (nonce == null || timestamp == null || typeof nonce === 'function') {
      return next(new Error('Invalid parameters'), false);
    }

    if (RedisNonceStore.isStale(timestamp)) {
      return next(new Error('Invalid or expired timestamp'), false);
    }

    // Pass all the parameter checks, now check to see if used
    return this.redis.get(nonce, (err, seen) => {
      if (seen) {
        return next(new Error('Nonce already seen'), false);
      }

      // Dont have to wait for callback b/c it's a sync op
      this.setUsed(nonce, timestamp);

      return next(null, true);
    });
  }

  setUsed(nonce, timestamp, next = noop) {
    this.redis.set(nonce, timestamp);
    this.redis.expire(nonce, EXPIRE_IN_SEC);

    return next(null);
  }
}

module.exports = RedisNonceStore;
