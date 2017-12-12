'use strict';

/**
 * Special encode is our encoding method that implements the encoding of
 * characters not defaulted by encodeURI.
 *
 * Specifically ' and !
 *
 * @param {string} string String to encode
 * @returns {string}
 */
exports.special_encode = function(string) {
  return encodeURIComponent(string)
    .replace(/[!'()]/g, escape)
    .replace(/\*/g, '%2A');
};
