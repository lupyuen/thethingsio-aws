//  region AWS Settings - FILL IN YOUR OWN AWS SETTINGS HERE
//  send_to_aws_kinesis is a thethings.io Cloud Function that sends the Cloud Function Params
//  (containing sensor data) as a JSON data record to the AWS Kinesis Stream declared below.

const AWSAccessKeyId = 'AKIAJCJ2TMJQ7JJ2QZ6A';
const AWSSecretAccessKey = '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';
const AWSRegion = 'ap-southeast-1';
const AWSKinesisStream = 'sigfox-sensor-stream';

//  /////////////////////////////////////////////////////////////////////////////// endregion
//  region AWS Kinesis Declarations (Do Not Change)

const AWSService = 'kinesis';
const AWSTarget = 'Kinesis_20131202.PutRecord';  //  Invoke the PutRecord API to add sensor records.
const AWSHost = `${AWSService}.${AWSRegion}.amazonaws.com`;  //  e.g. kinesis.us-west-2.amazonaws.com
const AWSEndpoint = `https://${AWSHost}/`;  //  e.g. https://kinesis.us-west-2.amazonaws.com/
const AWSQueryString = '';
const AWSMethod = 'POST';
const AWSContentType = 'application/x-amz-json-1.1';
const unittest = typeof process !== 'undefined' && process && process.env && process.env.UNITTEST;  //  True for unit test.
let fastsha256 = null;
let jsbase64 = null, Base64 = null;

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region Main Function

function main(params0, callback){
  //  Send the params as a JSON data record to the AWS Kinesis Stream declared above.
  //  Set the "timestamp" field if not set.
  const params = { timestamp: params0.timestamp };
  if (!params.timestamp) params.timestamp = new Date().toISOString();
  Object.assign(params, params0);  //  Copy all key-values.
  const base64Params = jsbase64.encode(JSON.stringify(params));  //  Params JSON doc encoded in Base64.
  const body = {
    StreamName: AWSKinesisStream,
    Data: base64Params,
    PartitionKey: '0',  //  Change this to compute the partition key if you need to support high data volume with multiple partitions.
    //  Optional Field: ExplicitHashKey, used to explicitly determine the shard the data record is assigned to by overriding the partition key hash.
    //  Optional Field: SequenceNumberForOrdering, guarantees strictly increasing sequence numbers, for puts from the same client and to the same partition key.
  };
  const para = {
    accessKey: AWSAccessKeyId,
    secretKey: AWSSecretAccessKey,
    method: AWSMethod,
    //  The part of the URI from domain to query.  '/' if no path.
    uri: '/' + AWSEndpoint.split('/').slice(3).join('/'),
    queryString: AWSQueryString,
    contentType: AWSContentType,
    host: AWSHost,
    body,
    region: AWSRegion,
    service: AWSService,
    target: AWSTarget,
  };
  //  Compose the signed AWS request header.
  const headers = composeAWSRequestHeader(para);

  //  Send the request.
  return sendAWSRequest(para, headers, callback);
}

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region AWS Request

function sendAWSRequest(para, headers, callback) {
  //  Send the signed AWS request.  Call the callback when done.
  const body = para.body;
  const req = {
    host: para.host,  //  e.g. kinesis.us-west-2.amazonaws.com
    path: para.uri + (
      para.queryString
        ? `?{para.queryString}`
        : ''
    ),
    port: 443,
    secure: true,
    method: para.method,
    headers,
  };
  console.log('*** sendAWSRequest', { req, body });
  //  httpRequest only sends JSON bodies, not string bodies.
  return httpRequest(req, body, (error, response) => {
    if (error) {  //  Suppress the error so caller won't retry.
      console.error('*** sendAWSRequest error', error.message, error.stack);
      return callback(null, error.message);
    }
    const result = response.result;
    console.log(['*** sendAWSRequest', new Date().toISOString(), JSON.stringify({ result, req, response }, null, 2)].join('-'.repeat(5)));
    console.log('response=', response);
    console.log('result=', result);
    return callback(null, result);
  });
}

/* From https://docs.aws.amazon.com/kinesis/latest/APIReference/API_PutRecord.html
Sample Request:
POST / HTTP/1.1
Host: kinesis.<region>.<domain>
Content-Length: <PayloadSizeBytes>
User-Agent: <UserAgentString>
Content-Type: application/x-amz-json-1.1
Authorization: <AuthParams>
Connection: Keep-Alive
X-Amz-Date: <Date>
X-Amz-Target: Kinesis_20131202.PutRecord
{
  "StreamName": "exampleStreamName",
  "Data": "XzxkYXRhPl8x",
  "PartitionKey": "partitionKey"
}

Sample Response:
HTTP/1.1 200 OK
x-amzn-RequestId: <RequestId>
Content-Type: application/x-amz-json-1.1
Content-Length: <PayloadSizeBytes>
Date: <Date>
{
  "SequenceNumber": "21269319989653637946712965403778482177",
  "ShardId": "shardId-000000000001"
}
 */

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region Functions for signing AWS requests

function composeAWSRequestHeader(para) {
  //  Compose a signed AWS request header. Based on https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html#sig-v4-examples-post
  //  TODO: Handle special characters in the URL.
  if (!para.accessKey) throw new Error('missing accessKey');
  if (!para.secretKey) throw new Error('missing secretKey');
  if (!para.method) throw new Error('missing method');
  if (!para.uri) throw new Error('missing uri');
  if (!para.queryString && para.queryString !== '') throw new Error('missing queryString');
  if (!para.contentType) throw new Error('missing contentType');
  if (!para.host) throw new Error('missing host');
  if (!para.body && para.body !== '') throw new Error('missing body');
  if (!para.region) throw new Error('missing region');
  if (!para.service) throw new Error('missing service');

  const now = new Date().toISOString();  //  e.g. "2018-04-28T07:19:47.414Z"
  // Get ISO 8601 format: YYYYMMDD'T'HHMMSS'Z' e.g. "20180428T072028Z"
  let amzDate = now.substr(0, 19).split('-').join('').split(':').join('') + 'Z';
  if (unittest && para.amzDate) { amzDate = para.amzDate; console.log('*** Unit Test:', { amzDate }) }
  //  Date without time, used in credential scope, e.g. "20180428"
  const datestamp = amzDate.substr(0, 8);

  // ************* TASK 1: CREATE A CANONICAL REQUEST *************
  // http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

  // Step 1 is to define the verb (GET, POST, etc.)
  // e.g. method = 'POST'

  // Step 2: Create canonical URI--the part of the URI from domain to query string (use '/' if no path)
  // e.g. uri = '/';

  // Step 3: Create the canonical query string. In this example, request
  // parameters are passed in the body of the request and the query string is blank.
  // e.g. queryString = '';

  // Step 4: Create the canonical headers. Header names must be trimmed and lowercase, and sorted in code point order
  // from low to high.  Add the target if any. Note that there is a trailing \n.
  let canonicalHeaders =
    'content-type:' + para.contentType + '\n' +
    'host:' + para.host + '\n' +
    'x-amz-date:' + amzDate + '\n';
  if (para.target) canonicalHeaders += 'x-amz-target:' + para.target + '\n';
  console.log({canonicalHeaders});

  // Step 5: Create the list of signed headers. This lists the headers in the canonicalHeaders list,
  // delimited with ";" and in alpha order. Note: The request can include any headers; canonicalHeaders and
  // signedHeaders include those that you want to be included in the hash of the request. "Host" and "x-amz-date" are
  // always required. For Kinesis, content-type and x-amz-target are also required.
  let signedHeaders = 'content-type;host;x-amz-date';
  if (para.target) signedHeaders += ';x-amz-target';
  console.log({signedHeaders});

  // Step 6: Create payload hash. In this example, the payload (body of the request) contains the request parameters.
  const body = JSON.stringify(para.body);
  const payloadHash = sha256hash(body);
  console.log({body});

  // Step 7: Combine elements to create canonical request
  const canonicalRequest = para.method + '\n' + para.uri + '\n' +
    para.queryString + '\n' + canonicalHeaders + '\n' +
    signedHeaders + '\n' + payloadHash;
  const canonicalRequestHash = sha256hash(canonicalRequest);
  console.log({canonicalRequest, canonicalRequestHash});

  // ************* TASK 2: CREATE THE STRING TO SIGN*************
  // Match the algorithm to the hashing algorithm you use, either SHA-1 or SHA-256 (recommended)
  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = datestamp + '/' + para.region + '/' + para.service + '/' + 'aws4_request';
  const stringToSign = algorithm + '\n' +  amzDate + '\n' +
    credentialScope + '\n' + canonicalRequestHash;
  console.log({stringToSign});

  // ************* TASK 3: CALCULATE THE SIGNATURE *************
  // Create the signing key using the function defined above.
  const signingKey = getSignatureKey(para.secretKey, datestamp, para.region, para.service);

  // Sign the stringToSign using the signingKey
  const signature = sha256hmac(stringToSign, signingKey);
  const signatureStr = byteArrayToHex(signature);  //  Convert to hex string.

  // ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
  // Put the signature information in a header named Authorization.
  const authorizationHeader = algorithm + ' ' +
    'Credential=' + para.accessKey + '/' + credentialScope + ', ' +
    'SignedHeaders=' + signedHeaders + ', ' +
    'Signature=' + signatureStr;
  console.log({authorizationHeader});

  // For Kinesis, the request can include any headers, but MUST include "host", "x-amz-date",
  // "x-amz-target", "content-type", and "Authorization". Except for the authorization header, the headers must be
  // included in the canonicalHeaders and signedHeaders values, as noted earlier. Order here is not significant.
  const headers = {
    'Content-Type': para.contentType,
    'Host': para.host,
    'X-Amz-Date': amzDate,
    'Authorization': authorizationHeader
  };
  if (para.target) headers['X-Amz-Target'] = para.target;

  // Unit Test: Check whether the signed authorization header matches the expected header.
  if (unittest && para.expectedAuthorizationHeader) {
    if (authorizationHeader === para.expectedAuthorizationHeader)
      console.log('*** Unit Test: Expected authorization header OK');
    else throw new Error([
      'Expected authorization header:',
      para.expectedAuthorizationHeader,
      'Got:',
      authorizationHeader,
    ].join('\n'));
  }
  //  Return the signed AWS request headers.
  return headers;
}

function getSignatureKey(key, dateStamp, regionName, serviceName) {
  //  Compute the key for signing the AWS request.
  const kDate = sha256hmac(dateStamp, "AWS4" + key);
  const kRegion = sha256hmac(regionName, kDate);
  const kService = sha256hmac(serviceName, kRegion);
  const kSigning = sha256hmac("aws4_request", kService);
  return kSigning;
}

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region SHA-256 Hash Functions

function sha256hmac(text, key) {
  //  Sign the text string with the key using SHA-256.  key may be a text string or a UTF8 byte array.
  //  Returns a UTF8 byte array.
  if (typeof text !== 'string') throw new Error('not_string');
  const binaryKey = (typeof key === 'string')
    ? stringToUtf8ByteArray(key)  //  Convert text key to binary.
    : key;  //  Key is already binary.
  return fastsha256.hmac(binaryKey, stringToUtf8ByteArray(text));
}

function sha256hash(text) {
  //  Hash the text string with SHA-256.  Returns a string of lowercase hex digits e.g. 'a1b2c3'
  if (typeof text !== 'string') throw new Error('not_string');
  const hash = fastsha256.hash(stringToUtf8ByteArray(text));
  return byteArrayToHex(hash);
}

function byteArrayToHex(arr) {
  //  Given an array of bytes, return a hex string like 'a1b2c3'.
  if (typeof arr === 'string') throw new Error('not_byte_array');
  const stringArr = [];
  for (const byte of arr) {
    let s = byte.toString(16).toLowerCase();
    if (s.length === 1) s = '0' + s;
    stringArr.push(s);
  }
  return stringArr.join('');
}

function stringToUtf8ByteArray(str) {
  //  Convert Unicode string to UTF-8 byte array.
  if (typeof str !== 'string') throw new Error('not_string');
  const out = [];
  let p = 0;
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 128) {
      out[p++] = c;
    } else if (c < 2048) {
      out[p++] = (c >> 6) | 192;
      out[p++] = (c & 63) | 128;
    } else if (
      ((c & 0xFC00) == 0xD800) && (i + 1) < str.length &&
      ((str.charCodeAt(i + 1) & 0xFC00) == 0xDC00)) {
      // Surrogate Pair
      c = 0x10000 + ((c & 0x03FF) << 10) + (str.charCodeAt(++i) & 0x03FF);
      out[p++] = (c >> 18) | 240;
      out[p++] = ((c >> 12) & 63) | 128;
      out[p++] = ((c >> 6) & 63) | 128;
      out[p++] = (c & 63) | 128;
    } else {
      out[p++] = (c >> 12) | 224;
      out[p++] = ((c >> 6) & 63) | 128;
      out[p++] = (c & 63) | 128;
    }
  }
  return out;
}


fastsha256 =
  //  Fast SHA-256 implementation (with 1 line of code change) from https://github.com/dchest/fast-sha256-js
  (function (root, factory) {
    // Hack to make all exports of this module sha256 function object properties.
    var exports = {};
    factory(exports);
    var sha256 = exports["default"];
    for (var k in exports) {
      sha256[k] = exports[k];
    }

    if (typeof module === 'object' && typeof module.exports === 'object') {
      module.exports = sha256;
    } else if (typeof define === 'function' && define.amd) {
      define(function() { return sha256; });
    } else {
      root.sha256 = sha256;
    }

    return exports; //// Added to https://github.com/dchest/fast-sha256-js

  })(this, function(exports) {
    "use strict";
    exports.__esModule = true;
// SHA-256 (+ HMAC and PBKDF2) for JavaScript.
//
// Written in 2014-2016 by Dmitry Chestnykh.
// Public domain, no warranty.
//
// Functions (accept and return Uint8Arrays):
//
//   sha256(message) -> hash
//   sha256.hmac(key, message) -> mac
//   sha256.pbkdf2(password, salt, rounds, dkLen) -> dk
//
//  Classes:
//
//   new sha256.Hash()
//   new sha256.HMAC(key)
//
    exports.digestLength = 32;
    exports.blockSize = 64;
// SHA-256 constants
    var K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
      0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
      0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
      0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
      0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
      0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
      0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
      0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    function hashBlocks(w, v, p, pos, len) {
      var a, b, c, d, e, f, g, h, u, i, j, t1, t2;
      while (len >= 64) {
        a = v[0];
        b = v[1];
        c = v[2];
        d = v[3];
        e = v[4];
        f = v[5];
        g = v[6];
        h = v[7];
        for (i = 0; i < 16; i++) {
          j = pos + i * 4;
          w[i] = (((p[j] & 0xff) << 24) | ((p[j + 1] & 0xff) << 16) |
            ((p[j + 2] & 0xff) << 8) | (p[j + 3] & 0xff));
        }
        for (i = 16; i < 64; i++) {
          u = w[i - 2];
          t1 = (u >>> 17 | u << (32 - 17)) ^ (u >>> 19 | u << (32 - 19)) ^ (u >>> 10);
          u = w[i - 15];
          t2 = (u >>> 7 | u << (32 - 7)) ^ (u >>> 18 | u << (32 - 18)) ^ (u >>> 3);
          w[i] = (t1 + w[i - 7] | 0) + (t2 + w[i - 16] | 0);
        }
        for (i = 0; i < 64; i++) {
          t1 = (((((e >>> 6 | e << (32 - 6)) ^ (e >>> 11 | e << (32 - 11)) ^
            (e >>> 25 | e << (32 - 25))) + ((e & f) ^ (~e & g))) | 0) +
            ((h + ((K[i] + w[i]) | 0)) | 0)) | 0;
          t2 = (((a >>> 2 | a << (32 - 2)) ^ (a >>> 13 | a << (32 - 13)) ^
            (a >>> 22 | a << (32 - 22))) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
          h = g;
          g = f;
          f = e;
          e = (d + t1) | 0;
          d = c;
          c = b;
          b = a;
          a = (t1 + t2) | 0;
        }
        v[0] += a;
        v[1] += b;
        v[2] += c;
        v[3] += d;
        v[4] += e;
        v[5] += f;
        v[6] += g;
        v[7] += h;
        pos += 64;
        len -= 64;
      }
      return pos;
    }
// Hash implements SHA256 hash algorithm.
    var Hash = /** @class */ (function () {
      function Hash() {
        this.digestLength = exports.digestLength;
        this.blockSize = exports.blockSize;
        // Note: Int32Array is used instead of Uint32Array for performance reasons.
        this.state = new Int32Array(8); // hash state
        this.temp = new Int32Array(64); // temporary state
        this.buffer = new Uint8Array(128); // buffer for data to hash
        this.bufferLength = 0; // number of bytes in buffer
        this.bytesHashed = 0; // number of total bytes hashed
        this.finished = false; // indicates whether the hash was finalized
        this.reset();
      }
      // Resets hash state making it possible
      // to re-use this instance to hash other data.
      Hash.prototype.reset = function () {
        this.state[0] = 0x6a09e667;
        this.state[1] = 0xbb67ae85;
        this.state[2] = 0x3c6ef372;
        this.state[3] = 0xa54ff53a;
        this.state[4] = 0x510e527f;
        this.state[5] = 0x9b05688c;
        this.state[6] = 0x1f83d9ab;
        this.state[7] = 0x5be0cd19;
        this.bufferLength = 0;
        this.bytesHashed = 0;
        this.finished = false;
        return this;
      };
      // Cleans internal buffers and re-initializes hash state.
      Hash.prototype.clean = function () {
        for (var i = 0; i < this.buffer.length; i++) {
          this.buffer[i] = 0;
        }
        for (var i = 0; i < this.temp.length; i++) {
          this.temp[i] = 0;
        }
        this.reset();
      };
      // Updates hash state with the given data.
      //
      // Optionally, length of the data can be specified to hash
      // fewer bytes than data.length.
      //
      // Throws error when trying to update already finalized hash:
      // instance must be reset to use it again.
      Hash.prototype.update = function (data, dataLength) {
        if (dataLength === void 0) { dataLength = data.length; }
        if (this.finished) {
          throw new Error("SHA256: can't update because hash was finished.");
        }
        var dataPos = 0;
        this.bytesHashed += dataLength;
        if (this.bufferLength > 0) {
          while (this.bufferLength < 64 && dataLength > 0) {
            this.buffer[this.bufferLength++] = data[dataPos++];
            dataLength--;
          }
          if (this.bufferLength === 64) {
            hashBlocks(this.temp, this.state, this.buffer, 0, 64);
            this.bufferLength = 0;
          }
        }
        if (dataLength >= 64) {
          dataPos = hashBlocks(this.temp, this.state, data, dataPos, dataLength);
          dataLength %= 64;
        }
        while (dataLength > 0) {
          this.buffer[this.bufferLength++] = data[dataPos++];
          dataLength--;
        }
        return this;
      };
      // Finalizes hash state and puts hash into out.
      //
      // If hash was already finalized, puts the same value.
      Hash.prototype.finish = function (out) {
        if (!this.finished) {
          var bytesHashed = this.bytesHashed;
          var left = this.bufferLength;
          var bitLenHi = (bytesHashed / 0x20000000) | 0;
          var bitLenLo = bytesHashed << 3;
          var padLength = (bytesHashed % 64 < 56) ? 64 : 128;
          this.buffer[left] = 0x80;
          for (var i = left + 1; i < padLength - 8; i++) {
            this.buffer[i] = 0;
          }
          this.buffer[padLength - 8] = (bitLenHi >>> 24) & 0xff;
          this.buffer[padLength - 7] = (bitLenHi >>> 16) & 0xff;
          this.buffer[padLength - 6] = (bitLenHi >>> 8) & 0xff;
          this.buffer[padLength - 5] = (bitLenHi >>> 0) & 0xff;
          this.buffer[padLength - 4] = (bitLenLo >>> 24) & 0xff;
          this.buffer[padLength - 3] = (bitLenLo >>> 16) & 0xff;
          this.buffer[padLength - 2] = (bitLenLo >>> 8) & 0xff;
          this.buffer[padLength - 1] = (bitLenLo >>> 0) & 0xff;
          hashBlocks(this.temp, this.state, this.buffer, 0, padLength);
          this.finished = true;
        }
        for (var i = 0; i < 8; i++) {
          out[i * 4 + 0] = (this.state[i] >>> 24) & 0xff;
          out[i * 4 + 1] = (this.state[i] >>> 16) & 0xff;
          out[i * 4 + 2] = (this.state[i] >>> 8) & 0xff;
          out[i * 4 + 3] = (this.state[i] >>> 0) & 0xff;
        }
        return this;
      };
      // Returns the final hash digest.
      Hash.prototype.digest = function () {
        var out = new Uint8Array(this.digestLength);
        this.finish(out);
        return out;
      };
      // Internal function for use in HMAC for optimization.
      Hash.prototype._saveState = function (out) {
        for (var i = 0; i < this.state.length; i++) {
          out[i] = this.state[i];
        }
      };
      // Internal function for use in HMAC for optimization.
      Hash.prototype._restoreState = function (from, bytesHashed) {
        for (var i = 0; i < this.state.length; i++) {
          this.state[i] = from[i];
        }
        this.bytesHashed = bytesHashed;
        this.finished = false;
        this.bufferLength = 0;
      };
      return Hash;
    }());
    exports.Hash = Hash;
// HMAC implements HMAC-SHA256 message authentication algorithm.
    var HMAC = /** @class */ (function () {
      function HMAC(key) {
        this.inner = new Hash();
        this.outer = new Hash();
        this.blockSize = this.inner.blockSize;
        this.digestLength = this.inner.digestLength;
        var pad = new Uint8Array(this.blockSize);
        if (key.length > this.blockSize) {
          (new Hash()).update(key).finish(pad).clean();
        }
        else {
          for (var i = 0; i < key.length; i++) {
            pad[i] = key[i];
          }
        }
        for (var i = 0; i < pad.length; i++) {
          pad[i] ^= 0x36;
        }
        this.inner.update(pad);
        for (var i = 0; i < pad.length; i++) {
          pad[i] ^= 0x36 ^ 0x5c;
        }
        this.outer.update(pad);
        this.istate = new Uint32Array(8);
        this.ostate = new Uint32Array(8);
        this.inner._saveState(this.istate);
        this.outer._saveState(this.ostate);
        for (var i = 0; i < pad.length; i++) {
          pad[i] = 0;
        }
      }
      // Returns HMAC state to the state initialized with key
      // to make it possible to run HMAC over the other data with the same
      // key without creating a new instance.
      HMAC.prototype.reset = function () {
        this.inner._restoreState(this.istate, this.inner.blockSize);
        this.outer._restoreState(this.ostate, this.outer.blockSize);
        return this;
      };
      // Cleans HMAC state.
      HMAC.prototype.clean = function () {
        for (var i = 0; i < this.istate.length; i++) {
          this.ostate[i] = this.istate[i] = 0;
        }
        this.inner.clean();
        this.outer.clean();
      };
      // Updates state with provided data.
      HMAC.prototype.update = function (data) {
        this.inner.update(data);
        return this;
      };
      // Finalizes HMAC and puts the result in out.
      HMAC.prototype.finish = function (out) {
        if (this.outer.finished) {
          this.outer.finish(out);
        }
        else {
          this.inner.finish(out);
          this.outer.update(out, this.digestLength).finish(out);
        }
        return this;
      };
      // Returns message authentication code.
      HMAC.prototype.digest = function () {
        var out = new Uint8Array(this.digestLength);
        this.finish(out);
        return out;
      };
      return HMAC;
    }());
    exports.HMAC = HMAC;
// Returns SHA256 hash of data.
    function hash(data) {
      var h = (new Hash()).update(data);
      var digest = h.digest();
      h.clean();
      return digest;
    }
    exports.hash = hash;
// Function hash is both available as module.hash and as default export.
    exports["default"] = hash;
// Returns HMAC-SHA256 of data under the key.
    function hmac(key, data) {
      var h = (new HMAC(key)).update(data);
      var digest = h.digest();
      h.clean();
      return digest;
    }
    exports.hmac = hmac;
// Derives a key from password and salt using PBKDF2-HMAC-SHA256
// with the given number of iterations.
//
// The number of bytes returned is equal to dkLen.
//
// (For better security, avoid dkLen greater than hash length - 32 bytes).
    function pbkdf2(password, salt, iterations, dkLen) {
      var prf = new HMAC(password);
      var len = prf.digestLength;
      var ctr = new Uint8Array(4);
      var t = new Uint8Array(len);
      var u = new Uint8Array(len);
      var dk = new Uint8Array(dkLen);
      for (var i = 0; i * len < dkLen; i++) {
        var c = i + 1;
        ctr[0] = (c >>> 24) & 0xff;
        ctr[1] = (c >>> 16) & 0xff;
        ctr[2] = (c >>> 8) & 0xff;
        ctr[3] = (c >>> 0) & 0xff;
        prf.reset();
        prf.update(salt);
        prf.update(ctr);
        prf.finish(u);
        for (var j = 0; j < len; j++) {
          t[j] = u[j];
        }
        for (var j = 2; j <= iterations; j++) {
          prf.reset();
          prf.update(u).finish(u);
          for (var k = 0; k < len; k++) {
            t[k] ^= u[k];
          }
        }
        for (var j = 0; j < len && i * len + j < dkLen; j++) {
          dk[i * len + j] = t[j];
        }
      }
      for (var i = 0; i < len; i++) {
        t[i] = u[i] = 0;
      }
      for (var i = 0; i < 4; i++) {
        ctr[i] = 0;
      }
      prf.clean();
      return dk;
    }
    exports.pbkdf2 = pbkdf2;
  });
//  End of https://github.com/dchest/fast-sha256-js

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region Base-64 Encoding Function
//  From https://raw.githubusercontent.com/dankogai/js-base64/master/base64.js with one line of code added.
/*
 *  base64.js
 *
 *  Licensed under the BSD 3-Clause License.
 *    http://opensource.org/licenses/BSD-3-Clause
 *
 *  References:
 *    http://en.wikipedia.org/wiki/Base64
 */
;(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined'
    ? module.exports = factory(global)
    : typeof define === 'function' && define.amd
    ? define(factory) : factory(global)
}((
  typeof self !== 'undefined' ? self
    : typeof window !== 'undefined' ? window
    : typeof global !== 'undefined' ? global
      : this
), function(global) {
  'use strict';
  // existing version for noConflict()
  var _Base64 = global.Base64;
  var version = "2.4.3";
  // if node.js, we use Buffer
  var buffer;
  if (typeof module !== 'undefined' && module.exports) {
    try {
      buffer = require('buffer').Buffer;
    } catch (err) {}
  }
  // constants
  var b64chars
    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var b64tab = function(bin) {
    var t = {};
    for (var i = 0, l = bin.length; i < l; i++) t[bin.charAt(i)] = i;
    return t;
  }(b64chars);
  var fromCharCode = String.fromCharCode;
  // encoder stuff
  var cb_utob = function(c) {
    if (c.length < 2) {
      var cc = c.charCodeAt(0);
      return cc < 0x80 ? c
        : cc < 0x800 ? (fromCharCode(0xc0 | (cc >>> 6))
          + fromCharCode(0x80 | (cc & 0x3f)))
          : (fromCharCode(0xe0 | ((cc >>> 12) & 0x0f))
            + fromCharCode(0x80 | ((cc >>>  6) & 0x3f))
            + fromCharCode(0x80 | ( cc         & 0x3f)));
    } else {
      var cc = 0x10000
        + (c.charCodeAt(0) - 0xD800) * 0x400
        + (c.charCodeAt(1) - 0xDC00);
      return (fromCharCode(0xf0 | ((cc >>> 18) & 0x07))
        + fromCharCode(0x80 | ((cc >>> 12) & 0x3f))
        + fromCharCode(0x80 | ((cc >>>  6) & 0x3f))
        + fromCharCode(0x80 | ( cc         & 0x3f)));
    }
  };
  var re_utob = /[\uD800-\uDBFF][\uDC00-\uDFFFF]|[^\x00-\x7F]/g;
  var utob = function(u) {
    return u.replace(re_utob, cb_utob);
  };
  var cb_encode = function(ccc) {
    var padlen = [0, 2, 1][ccc.length % 3],
      ord = ccc.charCodeAt(0) << 16
        | ((ccc.length > 1 ? ccc.charCodeAt(1) : 0) << 8)
        | ((ccc.length > 2 ? ccc.charCodeAt(2) : 0)),
      chars = [
        b64chars.charAt( ord >>> 18),
        b64chars.charAt((ord >>> 12) & 63),
        padlen >= 2 ? '=' : b64chars.charAt((ord >>> 6) & 63),
        padlen >= 1 ? '=' : b64chars.charAt(ord & 63)
      ];
    return chars.join('');
  };
  var btoa = global.btoa ? function(b) {
    return global.btoa(b);
  } : function(b) {
    return b.replace(/[\s\S]{1,3}/g, cb_encode);
  };
  var _encode = buffer ?
    buffer.from && Uint8Array && buffer.from !== Uint8Array.from
      ? function (u) {
        return (u.constructor === buffer.constructor ? u : buffer.from(u))
          .toString('base64')
      }
      :  function (u) {
        return (u.constructor === buffer.constructor ? u : new  buffer(u))
          .toString('base64')
      }
    : function (u) { return btoa(utob(u)) }
  ;
  var encode = function(u, urisafe) {
    return !urisafe
      ? _encode(String(u))
      : _encode(String(u)).replace(/[+\/]/g, function(m0) {
        return m0 == '+' ? '-' : '_';
      }).replace(/=/g, '');
  };
  var encodeURI = function(u) { return encode(u, true) };
  // decoder stuff
  var re_btou = new RegExp([
    '[\xC0-\xDF][\x80-\xBF]',
    '[\xE0-\xEF][\x80-\xBF]{2}',
    '[\xF0-\xF7][\x80-\xBF]{3}'
  ].join('|'), 'g');
  var cb_btou = function(cccc) {
    switch(cccc.length) {
      case 4:
        var cp = ((0x07 & cccc.charCodeAt(0)) << 18)
          |    ((0x3f & cccc.charCodeAt(1)) << 12)
          |    ((0x3f & cccc.charCodeAt(2)) <<  6)
          |     (0x3f & cccc.charCodeAt(3)),
          offset = cp - 0x10000;
        return (fromCharCode((offset  >>> 10) + 0xD800)
          + fromCharCode((offset & 0x3FF) + 0xDC00));
      case 3:
        return fromCharCode(
          ((0x0f & cccc.charCodeAt(0)) << 12)
          | ((0x3f & cccc.charCodeAt(1)) << 6)
          |  (0x3f & cccc.charCodeAt(2))
        );
      default:
        return  fromCharCode(
          ((0x1f & cccc.charCodeAt(0)) << 6)
          |  (0x3f & cccc.charCodeAt(1))
        );
    }
  };
  var btou = function(b) {
    return b.replace(re_btou, cb_btou);
  };
  var cb_decode = function(cccc) {
    var len = cccc.length,
      padlen = len % 4,
      n = (len > 0 ? b64tab[cccc.charAt(0)] << 18 : 0)
        | (len > 1 ? b64tab[cccc.charAt(1)] << 12 : 0)
        | (len > 2 ? b64tab[cccc.charAt(2)] <<  6 : 0)
        | (len > 3 ? b64tab[cccc.charAt(3)]       : 0),
      chars = [
        fromCharCode( n >>> 16),
        fromCharCode((n >>>  8) & 0xff),
        fromCharCode( n         & 0xff)
      ];
    chars.length -= [0, 0, 2, 1][padlen];
    return chars.join('');
  };
  var atob = global.atob ? function(a) {
    return global.atob(a);
  } : function(a){
    return a.replace(/[\s\S]{1,4}/g, cb_decode);
  };
  var _decode = buffer ?
    buffer.from && Uint8Array && buffer.from !== Uint8Array.from
      ? function(a) {
        return (a.constructor === buffer.constructor
          ? a : buffer.from(a, 'base64')).toString();
      }
      : function(a) {
        return (a.constructor === buffer.constructor
          ? a : new buffer(a, 'base64')).toString();
      }
    : function(a) { return btou(atob(a)) };
  var decode = function(a){
    return _decode(
      String(a).replace(/[-_]/g, function(m0) { return m0 == '-' ? '+' : '/' })
        .replace(/[^A-Za-z0-9\+\/]/g, '')
    );
  };
  var noConflict = function() {
    var Base64 = global.Base64;
    global.Base64 = _Base64;
    return Base64;
  };
  // export Base64
  global.Base64 = {
    VERSION: version,
    atob: atob,
    btoa: btoa,
    fromBase64: decode,
    toBase64: encode,
    utob: utob,
    encode: encode,
    encodeURI: encodeURI,
    btou: btou,
    decode: decode,
    noConflict: noConflict
  };
  // if ES5 is available, make Base64.extendString() available
  if (typeof Object.defineProperty === 'function') {
    var noEnum = function(v){
      return {value:v,enumerable:false,writable:true,configurable:true};
    };
    global.Base64.extendString = function () {
      Object.defineProperty(
        String.prototype, 'fromBase64', noEnum(function () {
          return decode(this)
        }));
      Object.defineProperty(
        String.prototype, 'toBase64', noEnum(function (urisafe) {
          return encode(this, urisafe)
        }));
      Object.defineProperty(
        String.prototype, 'toBase64URI', noEnum(function () {
          return encode(this, true)
        }));
    };
  }
  //
  // export Base64 to the namespace
  //
  if (global['Meteor']) { // Meteor.js
    Base64 = global.Base64;
  }
  // module.exports and AMD are mutually exclusive.
  // module.exports has precedence.
  if (typeof module !== 'undefined' && module.exports) {
    module.exports.Base64 = global.Base64;
  }
  else if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define([], function(){ return global.Base64 });
  }

  jsbase64 = global.Base64; //// Added to https://raw.githubusercontent.com/dankogai/js-base64/master/base64.js

  // that's it!
  return {Base64: global.Base64}
}));
//  End of https://raw.githubusercontent.com/dankogai/js-base64/master/base64.js

//  //////////////////////////////////////////////////////////////////////////////////// endregion
//  region Unit Test

//  Run Unit Test on local machine
if (unittest) {
  const params =
    {"tmp": 28.9}
  ; setTimeout(() => main(params, (error, result) =>
    console.log(error, result)), 1000);
}

let testPara = {};  //  Sample AWS requests for unit testing.
if (unittest) {
  testPara.sample = {  //  From https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    amzDate: unittest ? '20150830T123600Z' : null, ////
    accessKey: 'AKIDEXAMPLE',
    secretKey: AWSSecretAccessKey,
    method: 'GET',
    //  The part of the URI from domain to query.  '/' if no path.
    uri: '/',
    queryString: 'Action=ListUsers&Version=2010-05-08',
    contentType: 'application/x-www-form-urlencoded; charset=utf-8',
    host: 'iam.amazonaws.com',
    body: '',
    region: 'us-east-1',
    service: 'iam',
    expectedAuthorizationHeader: 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7',
  };
}

//  //////////////////////////////////////////////////////////////////////////////////// endregion
