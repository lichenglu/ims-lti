'use strict';

/*
 * Decaffeinate suggestions:
 * DS101: Remove unnecessary use of Array.from
 * DS102: Remove unnecessary code created because of implicit returns
 * DS103: Rewrite code to no longer use __guard__
 * DS205: Consider reworking code to avoid use of IIFEs
 * DS206: Consider reworking classes to avoid initClass
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const url = require('url');
const uuid = require('uuid');

const xml2js = require('xml2js');
const xml_builder = require('xmlbuilder');

const errors = require('../errors');
const HMAC_SHA1 = require('../hmac-sha1');
const utils = require('../utils');

const REQUEST_REPLACE = 'replaceResult';
const REQUEST_READ = 'readResult';
const REQUEST_DELETE = 'deleteResult';

function navigateXml(xmlObject, path) {
  for (const part of path.split('.')) {
    if (
      xmlObject == null ||
      xmlObject[part] == null ||
      xmlObject[part][0] == null
    ) {
      return;
    }

    xmlObject = xmlObject[part][0];
  }

  return xmlObject;
}

function parseResponse(body, callback) {
  xml2js.parseString(body, {trim: true}, (err, result) => {
    if (err != null) {
      callback(
        new errors.OutcomeResponseError(
          'The server responsed with an invalid XML document'
        ),
        false
      );
      return;
    }

    const response =
      result == null ? undefined : result.imsx_POXEnvelopeResponse;
    const code = navigateXml(
      response,
      'imsx_POXHeader.imsx_POXResponseHeaderInfo.imsx_statusInfo.imsx_codeMajor'
    );

    if (code !== 'success') {
      const msg = navigateXml(
        response,
        'imsx_POXHeader.imsx_POXResponseHeaderInfo.imsx_statusInfo.imsx_description'
      );

      callback(new errors.OutcomeResponseError(msg), false);
      return;
    }

    callback(null, true, response);
  });
}

class OutcomeDocument {
  static replace(source_did, payload, options) {
    const doc = new OutcomeDocument(REQUEST_REPLACE, source_did, options);

    if (payload == null) {
      return doc;
    }

    if (payload.score != null) {
      doc.add_score(payload.score);
    }

    if (payload.text != null) {
      doc.add_text(payload.text);
    }

    if (payload.url != null) {
      doc.add_url(payload.url);
    }

    return doc;
  }

  static read(source_did, options) {
    return new OutcomeDocument(REQUEST_READ, source_did, options);
  }

  static delete(source_did, options) {
    return new OutcomeDocument(REQUEST_DELETE, source_did, options);
  }

  constructor(type, source_did, options) {
    // Unlike OutcomeService, OutcomeDocument defaults to support any result type
    this.result_data_types = (options && options.result_data_types) || true;
    this.language = (options && options.language) || 'en';

    // Build and configure the document
    const xmldec = {
      version: '1.0',
      encoding: 'UTF-8'
    };

    this.doc = xml_builder.create('imsx_POXEnvelopeRequest', xmldec);
    this.doc.attribute(
      'xmlns',
      'http://www.imsglobal.org/services/ltiv1p1/xsd/imsoms_v1p0'
    );

    this.head = this.doc.ele('imsx_POXHeader').ele('imsx_POXRequestHeaderInfo');
    this.body = this.doc
      .ele('imsx_POXBody')
      .ele(type + 'Request')
      .ele('resultRecord');

    // Generate a unique identifier and apply the version to the header information
    this.head.ele('imsx_version', 'V1.0');
    this.head.ele('imsx_messageIdentifier', uuid.v1());

    // Apply the source DID to the body
    this.body.ele('sourcedGUID').ele('sourcedId', source_did);
  }

  add_score(score) {
    if (typeof score !== 'number' || score < 0 || score > 1.0) {
      throw new errors.ParameterError(
        'Score must be a floating point number >= 0 and <= 1'
      );
    }

    const eScore = this._result_ele().ele('resultScore');

    eScore.ele('language', this.language);
    eScore.ele('textString', score);
  }

  add_text(text) {
    this._add_payload('text', text);
  }

  add_url(url) {
    this._add_payload('url', url);
  }

  finalize() {
    return this.doc.end({pretty: true});
  }

  _result_ele() {
    if (!this.result) {
      this.result = this.body.ele('result');
    }

    return this.result;
  }

  _add_payload(type, value) {
    if (this.has_payload) {
      throw new errors.ExtensionError(
        'Result data payload has already been set'
      );
    }

    if (!this._supports_result_data(type)) {
      throw new errors.ExtensionError('Result data type is not supported');
    }

    this._result_ele()
      .ele('resultData')
      .ele(type, value);
    this.has_payload = true;
  }

  _supports_result_data(type) {
    if (!this.result_data_types || this.result_data_types.length === 0) {
      return false;
    }

    if (this.result_data_types === true) {
      return true;
    }

    if (type == null) {
      // Shouldn't be false?
      return true;
    }

    return this.result_data_types.indexOf(type) !== -1;
  }
}

class OutcomeService {
  constructor(options) {
    if (options == null) {
      options = {};
    }
    this.consumer_key = options.consumer_key;
    this.consumer_secret = options.consumer_secret;
    this.service_url = options.service_url;
    this.source_did = options.source_did;
    this.result_data_types = options.result_data_types || [];
    this.signer = options.signer || new HMAC_SHA1();
    this.cert_authority = options.cert_authority || null;
    this.language = options.language || 'en';

    // Break apart the service url into the url fragments for use by OAuth signing, additionally prepare the OAuth
    // specific url that used exclusively in the signing process.
    this.service_url_parts = url.parse(this.service_url, true);
    this.service_url_oauth =
      this.service_url_parts.protocol +
      '//' +
      this.service_url_parts.host +
      this.service_url_parts.pathname;
  }

  send_replace_result(score, callback) {
    this._send_replace_result({score}, callback);
  }

  send_replace_result_with_text(score, text, callback) {
    this._send_replace_result({score, text}, callback);
  }

  send_replace_result_with_url(score, url, callback) {
    this._send_replace_result({score, url}, callback);
  }

  _send_replace_result(payload, callback) {
    try {
      const doc = OutcomeDocument.replace(this.source_did, payload, this);

      this._send_request(doc, callback);
    } catch (err) {
      callback(err, false);
    }
  }

  send_read_result(callback) {
    const doc = OutcomeDocument.read(this.source_did, this);

    this._send_request(doc, (err, result, xml) => {
      if (err) {
        callback(err, result);
        return;
      }

      const score = parseFloat(
        navigateXml(
          xml,
          'imsx_POXBody.readResultResponse.result.resultScore.textString'
        ),
        10
      );

      if (isNaN(score)) {
        callback(
          new errors.OutcomeResponseError('Invalid score response'),
          false
        );
        return;
      }

      callback(null, score);
    });
  }

  send_delete_result(callback) {
    const doc = OutcomeDocument.delete(this.source_did, this);

    this._send_request(doc, callback);
  }

  supports_result_data(type) {
    // Deprecated
    return (
      this.result_data_types.length &&
      (!type || this.result_data_types.indexOf(type) !== -1)
    );
  }

  _send_request(doc, callback) {
    const xml = doc.finalize();
    let body = '';
    const is_ssl = this.service_url_parts.protocol === 'https:';

    const options = {
      hostname: this.service_url_parts.hostname,
      path: this.service_url_parts.path,
      method: 'POST',
      headers: this._build_headers(xml)
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
      res.on('data', chunk => {
        body += chunk;
      });
      return res.on('end', () => this._process_response(body, callback));
    });

    req.on('error', err => callback(err, false));
    req.write(xml);
    req.end();
  }

  _build_headers(body) {
    const headers = {
      oauth_version: '1.0',
      oauth_nonce: uuid.v4(),
      oauth_timestamp: Math.round(Date.now() / 1000),
      oauth_consumer_key: this.consumer_key,
      oauth_body_hash: crypto
        .createHash('sha1')
        .update(body)
        .digest('base64'),
      oauth_signature_method: 'HMAC-SHA1'
    };

    headers.oauth_signature = this.signer.build_signature_raw(
      this.service_url_oauth,
      this.service_url_parts,
      'POST',
      headers,
      this.consumer_secret
    );

    const auth = Object.keys(headers)
      .map(key => {
        const val = headers[key];

        return `${key}="${utils.special_encode(val)}"`;
      })
      .join(',');

    return {
      Authorization: `OAuth realm="",${auth}`,
      'Content-Type': 'application/xml',
      'Content-Length': body.length
    };
  }

  _process_response(body, callback) {
    // Deprecated
    return parseResponse(body, callback);
  }
}

// Deprecated
OutcomeService.REQUEST_REPLACE = REQUEST_REPLACE;
OutcomeService.REQUEST_READ = REQUEST_READ;
OutcomeService.REQUEST_DELETE = REQUEST_DELETE;

exports.init = function(provider) {
  if (
    !provider.body.lis_outcome_service_url ||
    !provider.body.lis_result_sourcedid
  ) {
    provider.outcome_service = false;
    return;
  }

  // The LTI 1.1 spec says that the language parameter is usually implied to be
  //  en, so the OutcomeService object defaults to en until the spec updates
  // and says there's other possible format options.
  const accepted_vals = provider.body.ext_outcome_data_values_accepted;

  provider.outcome_service = new OutcomeService({
    consumer_key: provider.consumer_key,
    consumer_secret: provider.consumer_secret,
    service_url: provider.body.lis_outcome_service_url,
    source_did: provider.body.lis_result_sourcedid,
    result_data_types: (accepted_vals && accepted_vals.split(',')) || [],
    signer: provider.signer
  });
};

exports.OutcomeDocument = OutcomeDocument;
exports.OutcomeService = OutcomeService;
exports.parseResponse = parseResponse;
