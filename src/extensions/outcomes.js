/*
 * decaffeinate suggestions:
 * DS101: Remove unnecessary use of Array.from
 * DS102: Remove unnecessary code created because of implicit returns
 * DS103: Rewrite code to no longer use __guard__
 * DS205: Consider reworking code to avoid use of IIFEs
 * DS206: Consider reworking classes to avoid initClass
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const crypto       = require('crypto');
const http         = require('http');
const https        = require('https');
const url          = require('url');
const uuid         = require('uuid');


const xml2js       = require('xml2js');
const xml_builder  = require('xmlbuilder');

const errors       = require('../errors');
const HMAC_SHA1    = require('../hmac-sha1');
const utils        = require('../utils');

const REQUEST_REPLACE = 'replaceResult';
const REQUEST_READ    = 'readResult';
const REQUEST_DELETE  = 'deleteResult';


const navigateXml = function(xmlObject, path) {
  for (let part of Array.from(path.split('.'))) {
    xmlObject = __guard__(xmlObject != null ? xmlObject[part] : undefined, x => x[0]);
  }

  return xmlObject;
};


const parseResponse = (body, callback) =>
  xml2js.parseString(body, {trim: true}, (err, result) => {
    if (err != null) {
      callback(new errors.OutcomeResponseError('The server responsed with an invalid XML document'), false);
      return;
    }

    const response  = result != null ? result.imsx_POXEnvelopeResponse : undefined;
    const code      = navigateXml(response, 'imsx_POXHeader.imsx_POXResponseHeaderInfo.imsx_statusInfo.imsx_codeMajor');

    if (code !== 'success') {
      const msg = navigateXml(response, 'imsx_POXHeader.imsx_POXResponseHeaderInfo.imsx_statusInfo.imsx_description');
      return callback(new errors.OutcomeResponseError(msg), false);
    } else {
      return callback(null, true, response);
    }
  })
;



class OutcomeDocument {

  static replace(source_did, payload, options) {
    const doc = new OutcomeDocument(REQUEST_REPLACE, source_did, options);

    if ((payload == null)) {
      return doc;
    }

    if (payload.score != null) { doc.add_score(payload.score); }
    if (payload.text != null) { doc.add_text(payload.text); }
    if (payload.url != null) { doc.add_url(payload.url); }

    return doc;
  }


  static read(source_did, options) {
    let doc;
    return doc = new OutcomeDocument(REQUEST_READ, source_did, options);
  }


  static delete(source_did, options) {
    let doc;
    return doc = new OutcomeDocument(REQUEST_DELETE, source_did, options);
  }


  constructor(type, source_did, options) {
    // unlike OutcomeService, OutcomeDocument defaults to support any result type
    this.result_data_types = (options != null ? options.result_data_types : undefined) || true;
    this.language = (options != null ? options.language : undefined) || 'en';

    // Build and configure the document
    const xmldec = {
      version:     '1.0',
      encoding:    'UTF-8'
    };

    this.doc = xml_builder.create('imsx_POXEnvelopeRequest', xmldec);
    this.doc.attribute('xmlns', 'http://www.imsglobal.org/services/ltiv1p1/xsd/imsoms_v1p0');

    this.head = this.doc.ele('imsx_POXHeader').ele('imsx_POXRequestHeaderInfo');
    this.body = this.doc.ele('imsx_POXBody').ele(type + 'Request').ele('resultRecord');

    // Generate a unique identifier and apply the version to the header information
    this.head.ele('imsx_version', 'V1.0');
    this.head.ele('imsx_messageIdentifier', uuid.v1());

    // Apply the source DID to the body
    this.body.ele('sourcedGUID').ele('sourcedId', source_did);
  }


  add_score(score) {
    if ((typeof score !== 'number') || (score < 0) || (score > 1.0)) {
      throw new errors.ParameterError('Score must be a floating point number >= 0 and <= 1');
    }

    const eScore = this._result_ele().ele('resultScore');
    eScore.ele('language', this.language);
    return eScore.ele('textString', score);
  }


  add_text(text) {
    return this._add_payload('text', text);
  }

  add_url(url) {
    return this._add_payload('url', url);
  }


  finalize() {
    return this.doc.end({pretty: true});
  }


  _result_ele() {
    return this.result || (this.result = this.body.ele('result'));
  }


  _add_payload(type, value) {
    if (this.has_payload) { throw new errors.ExtensionError('Result data payload has already been set'); }
    if (!this._supports_result_data(type)) { throw new errors.ExtensionError('Result data type is not supported'); }
    this._result_ele().ele('resultData').ele(type, value);
    return this.has_payload = true;
  }


  _supports_result_data(type) {
    if (!this.result_data_types || (this.result_data_types.length === 0)) {
      return false;
    }

    if (this.result_data_types === true) {
      return true;
    }

    if ((type == null)) {
      // Shouldn't be false?
      return true;
    }

    return this.result_data_types.indexOf(type) !== -1;
  }
}



class OutcomeService {
  static initClass() {
  
    // deprecated
    this.prototype.REQUEST_REPLACE = REQUEST_REPLACE;
    this.prototype.REQUEST_READ =    REQUEST_READ;
    this.prototype.REQUEST_DELETE =  REQUEST_DELETE;
  }

  constructor(options) {
    if (options == null) { options = {}; }
    this.consumer_key = options.consumer_key;
    this.consumer_secret = options.consumer_secret;
    this.service_url = options.service_url;
    this.source_did = options.source_did;
    this.result_data_types = options.result_data_types || [];
    this.signer = options.signer || (new HMAC_SHA1());
    this.cert_authority = options.cert_authority || null;
    this.language = options.language || 'en';

    // Break apart the service url into the url fragments for use by OAuth signing, additionally prepare the OAuth
    // specific url that used exclusively in the signing process.
    const parts = (this.service_url_parts = url.parse(this.service_url, true));
    this.service_url_oauth = parts.protocol + '//' + parts.host + parts.pathname;
  }


  send_replace_result(score, callback) {
    return this._send_replace_result({score}, callback);
  }


  send_replace_result_with_text(score, text, callback) {
    return this._send_replace_result({score, text}, callback);
  }


  send_replace_result_with_url(score, url, callback) {
    return this._send_replace_result({score, url}, callback);
  }


  _send_replace_result(payload, callback) {
    try {
      const doc = OutcomeDocument.replace(this.source_did, payload, this);
      return this._send_request(doc, callback);
    } catch (err) {
      return callback(err, false);
    }
  }


  send_read_result(callback) {
    const doc = OutcomeDocument.read(this.source_did, this);
    return this._send_request(doc, (err, result, xml) => {
      if (err) { return callback(err, result); }

      const score = parseFloat(navigateXml(xml, 'imsx_POXBody.readResultResponse.result.resultScore.textString'), 10);

      if (isNaN(score)) {
        return callback(new errors.OutcomeResponseError('Invalid score response'), false);
      } else {
        return callback(null, score);
      }
    });
  }


  send_delete_result(callback) {
    const doc = OutcomeDocument.delete(this.source_did, this);
    return this._send_request(doc, callback);
  }


  supports_result_data(type) {
    // deprecated
    return this.result_data_types.length && (!type || (this.result_data_types.indexOf(type) !== -1));
  }


  _send_request(doc, callback) {
    const xml     = doc.finalize();
    let body    = '';
    const is_ssl  = this.service_url_parts.protocol === 'https:';

    const options = {
      hostname:  this.service_url_parts.hostname,
      path:      this.service_url_parts.path,
      method:    'POST',
      headers:   this._build_headers(xml)
    };

    if (this.cert_authority && is_ssl) {
      options.ca = this.cert_authority;
    } else {
      options.agent = is_ssl ? https.globalAgent : http.globalAgent;
    }

    if (this.service_url_parts.port) {
      options.port = this.service_url_parts.port;
    }

    // Make the request to the TC, verifying that the status code is valid and fetching the entire response body.
    const req = (is_ssl ? https : http).request(options, res => {
      res.setEncoding('utf8');
      res.on('data', chunk => body += chunk);
      return res.on('end', () => {
        return this._process_response(body, callback);
      });
    });

    req.on('error', err => {
      return callback(err, false);
    });

    req.write(xml);
    return req.end();
  }


  _build_headers(body) {
    const headers = {
      oauth_version:           '1.0',
      oauth_nonce:             uuid.v4(),
      oauth_timestamp:         Math.round(Date.now() / 1000),
      oauth_consumer_key:      this.consumer_key,
      oauth_body_hash:         crypto.createHash('sha1').update(body).digest('base64'),
      oauth_signature_method:  'HMAC-SHA1'
    };

    headers.oauth_signature = this.signer.build_signature_raw(this.service_url_oauth, this.service_url_parts, 'POST', headers, this.consumer_secret);

    return {
      Authorization:     'OAuth realm="",' + ((() => {
        const result = [];
        for (let key in headers) {
          const val = headers[key];
          result.push(`${key}=\"${utils.special_encode(val)}\"`);
        }
        return result;
      })()).join(','),
      'Content-Type':    'application/xml',
      'Content-Length':  body.length
    };
  }


  _process_response(body, callback) {
    // deprecated
    return parseResponse(body, callback);
  }
}
OutcomeService.initClass();


exports.init = function(provider) {
  if (provider.body.lis_outcome_service_url && provider.body.lis_result_sourcedid) {
    // The LTI 1.1 spec says that the language parameter is usually implied to be en, so the OutcomeService object
    // defaults to en until the spec updates and says there's other possible format options.
    const accepted_vals = provider.body.ext_outcome_data_values_accepted;
    return provider.outcome_service = new OutcomeService({
      consumer_key: provider.consumer_key,
      consumer_secret: provider.consumer_secret,
      service_url: provider.body.lis_outcome_service_url,
      source_did: provider.body.lis_result_sourcedid,
      result_data_types: (accepted_vals && accepted_vals.split(',')) || [],
      signer: provider.signer
    });
  } else {
    return provider.outcome_service = false;
  }
};

exports.OutcomeDocument = OutcomeDocument;
exports.OutcomeService = OutcomeService;
exports.parseResponse = parseResponse;

function __guard__(value, transform) {
  return (typeof value !== 'undefined' && value !== null) ? transform(value) : undefined;
}