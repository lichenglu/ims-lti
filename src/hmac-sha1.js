/*
 * decaffeinate suggestions:
 * DS101: Remove unnecessary use of Array.from
 * DS102: Remove unnecessary code created because of implicit returns
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const crypto    = require('crypto');
const url       = require('url');
const utils     = require('./utils');


// Cleaning invloves:
//   stripping the oauth_signature from the params
//   encoding the values ( yes this double encodes them )
//   sorting the key/value pairs
//   joining them with &
//   encoding them again
//
// Returns a string representing the request
const _clean_request_body = function(body, query) {

  const out = [];

  const encodeParam = (key, val) => `${key}=${utils.special_encode(val)}`;

  const cleanParams = function(params) {
    if (typeof params !== 'object') { return; }

    for (let key in params) {
      const vals = params[key];
      if (key === 'oauth_signature') { continue; }
      if (Array.isArray(vals) === true) {
        for (let val of Array.from(vals)) {
          out.push(encodeParam(key, val));
        }
      } else {
        out.push(encodeParam(key, vals));
      }
    }

  };

  cleanParams(body);
  cleanParams(query);

  return utils.special_encode(out.sort().join('&'));
};



class HMAC_SHA1 {

  constructor(options) {
    this.trustProxy = (options && options.trustProxy) || false;
  }

  toString() {
    return 'HMAC_SHA1';
  }

  build_signature_raw(req_url, parsed_url, method, params, consumer_secret, token) {
    const sig = [
      method.toUpperCase(),
      utils.special_encode(req_url),
      _clean_request_body(params, parsed_url.query)
    ];

    return this.sign_string(sig.join('&'), consumer_secret, token);
  }

  host(req) {
    if (!this.trustProxy) {
      return req.headers.host;
    }

    return req.headers['x-forwarded-host'] || req.headers.host;
  }

  protocol(req) {
    const xprotocol = req.headers['x-forwarded-proto'];
    if (this.trustProxy && xprotocol) {
      return xprotocol;
    }

    if (req.protocol) {
      return req.protocol;
    }

    if (req.connection.encrypted) { return 'https'; } else { return 'http'; }
  }

  build_signature(req, body, consumer_secret, token) {
    const hapiRawReq = req.raw && req.raw.req;
    if (hapiRawReq) {
      req = hapiRawReq;
    }

    let originalUrl = req.originalUrl || req.url;
    const host = this.host(req);
    const protocol = this.protocol(req);

    // Since canvas includes query parameters in the body we can omit the query string
    if ((body.tool_consumer_info_product_family_code === 'canvas') || (body.tool_consumer_info_product_family_code === 'schoology')) {
      originalUrl = url.parse(originalUrl).pathname;
    }

    const parsedUrl  = url.parse(originalUrl, true);
    const hitUrl     = protocol + '://' + host + parsedUrl.pathname;

    return this.build_signature_raw(hitUrl, parsedUrl, req.method, body, consumer_secret, token);
  }

  sign_string(str, key, token) {
    key = `${key}&`;
    if (token) { key += token; }

    return crypto.createHmac('sha1', key).update(str).digest('base64');
  }
}

const exports = (module.exports = HMAC_SHA1);
