'use strict';

/*
 * Decaffeinate suggestions:
 * DS101: Remove unnecessary use of Array.from
 * DS102: Remove unnecessary code created because of implicit returns
 * DS103: Rewrite code to no longer use __guard__
 * DS207: Consider shorter variations of null checks
 * DS208: Avoid top-level this
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const crypto = require('crypto');
const http = require('http');
const url = require('url');
const uuid = require('uuid');
const should = require('should');

const dom = require('xmldom');
const xpath = require('xpath');
const xml_builder = require('xmlbuilder');

const HmacSha1 = require('../src/hmac-sha1');

const noop = () => undefined;
const omsNS = 'http://www.imsglobal.org/services/ltiv1p1/xsd/imsoms_v1p0';
const selectNode = xpath.useNamespaces({oms: omsNS});

// Standard nonce tests
//
exports.shouldBehaveLikeNonce = function(newStore = noop) {
  before(function() {
    this.store = newStore();
  });

  describe('.isNew', function() {
    it('should exist', function() {
      should.exist(this.store.isNew);
    });

    it('should return false if undefined passed', function(done) {
      const store = newStore();

      store.isNew(undefined, undefined, function(err, valid) {
        err.should.not.equal(null);
        valid.should.equal(false);
        done();
      });
    });

    it('should return false if no nonce but timestamp', function(done) {
      const store = newStore();

      store.isNew(undefined, Math.round(Date.now() / 1000), function(
        err,
        valid
      ) {
        err.should.not.equal(null);
        valid.should.equal(false);
        done();
      });
    });

    it('should return false if nonce but no timestamp', function(done) {
      const store = newStore();

      store.isNew('1', undefined, function(err, valid) {
        err.should.not.equal(null);
        valid.should.equal(false);
        done();
      });
    });

    it('should return true for new nonces', function(done) {
      const store = newStore();
      const now = Math.round(Date.now() / 1000);

      const nonce_one = `true-for-new-1-${Math.random() * 1000}`;
      const nonce_two = `true-for-new-2-${Math.random() * 1000}`;

      store.isNew(nonce_one, now, function(err, valid) {
        should.not.exist(err);
        valid.should.equal(true);

        store.isNew(nonce_two, now + 1, function(err, valid) {
          should.not.exist(err);
          valid.should.equal(true);
          done();
        });
      });
    });

    it('should return false for used nonces', function(done) {
      const store = newStore();
      const now = Math.round(Date.now() / 1000);

      const nonce = `should-return-false-for-used-${Math.random() * 1000}`;

      store.isNew(nonce, now, function(err, valid) {
        should.not.exist(err);
        valid.should.equal(true);

        store.isNew(nonce, now + 1, function(err, valid) {
          should.exist(err);
          valid.should.equal(false);
          done();
        });
      });
    });

    it('should return true for time-relivant nonces', function(done) {
      const store = newStore();

      const now = Math.round(Date.now() / 1000);
      const future = now + 1 * 60;
      const past_minute = now - 1 * 60;
      const past_two_minutes = now - 2 * 60;

      function first_test() {
        store.isNew('tr-00', now, function(err, valid) {
          should.not.exist(err);
          valid.should.equal(true);
          second_test();
        });
      }

      function second_test() {
        store.isNew('tr-11', future, function(err, valid) {
          should.not.exist(err);
          valid.should.equal(true);
          third_test();
        });
      }

      function third_test() {
        store.isNew('tr-01', past_minute, function(err, valid) {
          should.not.exist(err);
          valid.should.equal(true);
          fourth_test();
        });
      }

      function fourth_test() {
        store.isNew('tr-02', past_two_minutes, function(err, valid) {
          should.not.exist(err);
          valid.should.equal(true);
          done();
        });
      }

      first_test();
    });

    it('should return false for expired nonces', function(done) {
      const store = newStore();

      const now = Math.round(Date.now() / 1000);
      const five_and_one_sec_old = now - 5 * 60 - 1;
      const hour_old = now - 60 * 60;

      function first_test() {
        store.isNew('00', five_and_one_sec_old, function(err, valid) {
          should.exist(err);
          valid.should.equal(false);
          second_test();
        });
      }

      function second_test() {
        store.isNew('11', hour_old, function(err, valid) {
          should.exist(err);
          valid.should.equal(false);
          done();
        });
      }

      first_test();
    });
  });

  describe('.setUsed', function() {
    it('should exist', function() {
      should.exist(this.store.setUsed);
    });

    it('should set nonces to used', function(done) {
      const store = newStore();
      const now = Math.round(Date.now() / 1000);

      store.setUsed('11', now, function() {
        store.isNew('11', now + 1, function(err, valid) {
          should.exist(err);
          valid.should.equal(false);
          done();
        });
      });
    });
  });
};

/**
 * Creates a webserver that can respond to the outcomes service
 *
 * @returns {object}
 */
exports.outcomesWebServer = function() {
  return http.createServer((req, res) => {
    const path = url.parse(req.url);
    const handler =
      path.pathname === '/service/url' ? outcomesHandler : notFoundHandler;

    return handler(req, res);
  });
};

function outcomesHandler(req, res) {
  let body = '';

  req.on('data', buffer => {
    body += buffer.toString('utf8');
  });

  req.on('end', () => {
    try {
      verifySignature(req, body);
    } catch (e) {
      invalidSignatureError(res);
    }

    const doc = new dom.DOMParser().parseFromString(body);
    const request = getRequest(doc);
    const requestType = request.tagName || 'undefinedRequest';

    try {
      switch (requestType) {
        case 'replaceResultRequest':
          verifyDoc(doc);
          verifyScore(doc);

          return validScoreResponse(res);

        case 'readResultRequest':
          verifyDoc(doc);

          return validReadResponse(res);

        case 'deleteResultRequest':
          verifyDoc(doc);

          return validDeleteResponse(res);

        default:
          return outcomeTypeNotFoundHandler(res, requestType);
      }
    } catch (e) {
      return invalidOutcomeDocumentRequest(res, e.message);
    }
  });
}

function validScoreResponse(res, id, score) {
  res.writeHead(200, {'Content-Type': 'application/xml'});

  const doc = buildXmlDocument();
  const head = doc.ele('imsx_POXHeader').ele('imsx_POXResponseHeaderInfo');

  doc.ele('imsx_POXBody').ele('replaceResultResponse');

  head.ele('imsx_version', 'V1.0');
  head.ele('imsx_messageIdentifier', uuid.v4());

  const sub_head = head.ele('imsx_statusInfo');

  sub_head.ele('imsx_codeMajor', 'success');
  sub_head.ele('imsx_severity', 'status');
  sub_head.ele('imsx_description', `The score for ${id} is now ${score}`);
  sub_head.ele('imsx_messageRefIdentifier', uuid.v4());
  sub_head.ele('imsx_operationRefIdentifier', 'replaceResult');

  res.end(doc.end() + '\n');
}

function validReadResponse(res) {
  res.writeHead(200, {'Content-Type': 'application/xml'});

  const doc = buildXmlDocument();
  const head = doc.ele('imsx_POXHeader').ele('imsx_POXResponseHeaderInfo');

  const result = doc
    .ele('imsx_POXBody')
    .ele('readResultResponse')
    .ele('result')
    .ele('resultScore');

  result.ele('language', 'en');
  result.ele('textString', '.5');

  head.ele('imsx_version', 'V1.0');
  head.ele('imsx_messageIdentifier', uuid.v4());

  const sub_head = head.ele('imsx_statusInfo');

  sub_head.ele('imsx_codeMajor', 'success');
  sub_head.ele('imsx_severity', 'status');
  sub_head.ele('imsx_description', 'Result read');
  sub_head.ele('imsx_messageRefIdentifier', uuid.v4());
  sub_head.ele('imsx_operationRefIdentifier', 'readResult');

  res.end(doc.end() + '\n');
}

function validDeleteResponse(res) {
  res.writeHead(200, {'Content-Type': 'application/xml'});

  const doc = buildXmlDocument();
  const head = doc.ele('imsx_POXHeader').ele('imsx_POXResponseHeaderInfo');

  doc.ele('imsx_POXBody').ele('deleteResultResponse');

  head.ele('imsx_version', 'V1.0');
  head.ele('imsx_messageIdentifier', uuid.v4());

  const sub_head = head.ele('imsx_statusInfo');

  sub_head.ele('imsx_codeMajor', 'success');
  sub_head.ele('imsx_severity', 'status');
  sub_head.ele('imsx_description', 'Result deleted');
  sub_head.ele('imsx_messageRefIdentifier', uuid.v4());
  sub_head.ele('imsx_operationRefIdentifier', 'deleteResult');

  res.end(doc.end() + '\n');
}

function outcomeTypeNotFoundHandler(res, type) {
  res.writeHead(404, {'Content-Type': 'application/xml'});

  const doc = buildXmlDocument();
  const head = doc.ele('imsx_POXHeader').ele('imsx_POXResponseHeaderInfo');

  doc.ele('imsx_POXBody');

  head.ele('imsx_version', 'V1.0');
  head.ele('imsx_messageIdentifier', uuid.v4());

  const sub_head = head.ele('imsx_statusInfo');

  sub_head.ele('imsx_codeMajor', 'unsupported');
  sub_head.ele('imsx_severity', 'status');
  sub_head.ele('imsx_description', `${type} is not supported`);
  sub_head.ele('imsx_messageRefIdentifier', uuid.v4());
  sub_head.ele('imsx_operationRefIdentifier', type);

  res.end(doc.end() + '\n');
}

function notFoundHandler(req, res) {
  res.writeHead(404, {'Content-Type': 'text/html'});
  return res.end('Page not found');
}

function invalidSignatureError(res) {
  res.writeHead(403, {'Content-Type': 'application/xml'});

  const doc = buildXmlDocument();
  const head = doc.ele('imsx_POXHeader').ele('imsx_POXResponseHeaderInfo');

  doc.ele('imsx_POXBody');

  head.ele('imsx_version', 'V1.0');
  head.ele('imsx_messageIdentifier', uuid.v4());

  const sub_head = head.ele('imsx_statusInfo');

  sub_head.ele('imsx_codeMajor', 'failure');
  sub_head.ele('imsx_severity', 'signature');
  sub_head.ele('imsx_description', 'The signature provided is not valid');
  sub_head.ele('imsx_messageRefIdentifier', uuid.v4());
  sub_head.ele('imsx_operationRefIdentifier', 'signature');

  res.end(doc.end() + '\n');
}

function invalidOutcomeDocumentRequest(res, message) {
  res.writeHead(403, {'Content-Type': 'application/xml'});

  const doc = buildXmlDocument();
  const head = doc.ele('imsx_POXHeader').ele('imsx_POXResponseHeaderInfo');

  doc.ele('imsx_POXBody');

  head.ele('imsx_version', 'V1.0');
  head.ele('imsx_messageIdentifier', uuid.v4());

  const sub_head = head.ele('imsx_statusInfo');

  sub_head.ele('imsx_codeMajor', 'failure');
  sub_head.ele('imsx_severity', 'request');
  sub_head.ele('imsx_description', `Invalid request: ${message}`);
  sub_head.ele('imsx_messageRefIdentifier', uuid.v4());
  sub_head.ele('imsx_operationRefIdentifier', 'request');

  res.end(doc.end() + '\n');
}

function buildXmlDocument(type) {
  // Build and configure the document
  if (type == null) {
    type = 'Request';
  }
  const xmldec = {
    version: '1.0',
    encoding: 'UTF-8'
  };

  const doc = xml_builder.create('imsx_POXEnvelopeResponse', xmldec);

  doc.attribute(
    'xmlns',
    'http://www.imsglobal.org/services/ltiv1p1/xsd/imsoms_v1p0'
  );

  return doc;
}

function verifySignature(req, body) {
  const params = {};
  const signer = new HmacSha1();
  const service_url = 'http://127.0.0.1:1337/service/url';

  should(req.headers.authorization).be.a.String();

  for (const param of req.headers.authorization.split(',')) {
    const parts = param.split('=');

    params[decodeURIComponent(parts[0])] = cleanupValue(parts[1]);
  }

  delete params['OAuth realm'];

  const body_signature = crypto
    .createHash('sha1')
    .update(body)
    .digest('base64');
  const req_signature = signer.build_signature_raw(
    service_url,
    url.parse(service_url),
    'POST',
    params,
    'secret'
  );

  body_signature.should.equal(params.oauth_body_hash);
  req_signature.should.equal(params.oauth_signature);
}

function cleanupValue(value) {
  return decodeURIComponent(value.substr(1, value.length - 2));
}

function getRequest(doc) {
  const requests = selectNode(
    '/oms:imsx_POXEnvelopeRequest/oms:imsx_POXBody/*' +
      '| /imsx_POXEnvelopeRequest/imsx_POXBody/*',
    doc
  );

  should.exist(requests);
  should(requests).have.lengthOf(1);

  return requests.pop();
}

function verifyDoc(doc) {
  verifyNS(doc);
  verifySourceDid(doc);
}

function verifyNS(doc) {
  const body = selectNode(`//*[local-name(.) = 'imsx_POXBody']`, doc);
  const useNS = body.namespaceURI != null;

  if (useNS) {
    should(body.namespaceURI).be(omsNS);
  }
}

function verifySourceDid(doc) {
  const sourcedid = selectNode(
    '//resultRecord/sourcedGUID/sourcedId' +
      '| //oms:resultRecord/oms:sourcedGUID/oms:sourcedId',
    doc
  );

  should.exist(sourcedid);
  should(sourcedid).have.lengthOf(1);
  should(sourcedid.toString().trim()).not.be.empty();
}

function verifyScore(doc) {
  const scoreText = selectNode(
    'string(//replaceResultRequest/resultRecord/result/resultScore/textString' +
      '| //oms:replaceResultRequest/oms:resultRecord/oms:result/oms:resultScore/oms:textString)',
    doc
  );
  const score = parseFloat(scoreText.trim(), 10);

  should(score).be.within(0, 1);
}
