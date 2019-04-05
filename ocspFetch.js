// external dependencies
const rfc2560 = require('asn1.js-rfc2560');
const rfc5280 = require('asn1.js-rfc5280');
const fs = require('fs');
const WebCrypto = require('node-webcrypto-ossl');
const crypto = new WebCrypto();
const fetch = require('node-fetch');

/**
 * Adaptation of ocsp.utils.toDER helper function from node ocsp library.
 * @param {Buffer} raw Data to be written in DER format
 * @param {Buffer} what Type of DER output (e.g. "CERTIFICATE")
 * @return {Buffer} Data written in DER format
 */
const toDER = (raw, what) => {
  let der = raw
    .toString()
    .match(new RegExp('-----BEGIN ' + what + '-----([^-]*)-----END ' + what + '-----'));
  if (der) der = new Buffer(der[1].replace(/[\r\n]/g, ''), 'base64');
  else if (typeof raw === 'string') der = new Buffer(raw);
  else der = raw;
  return der;
};

/**
 * Adaptation of sha1 helper function from node ocsp library.
 * @param {Bytes} data Data to be hashed
 * @return {Buffer} Data hashed with SHA1 algorithm.
 */
const sha1 = async data => {
  return Buffer.from(await crypto.subtle.digest('SHA-1', data));
};

/**
 * Adaptation of ocsp.request.generate from node ocsp library.
 * @param {Buffer} rawCert certificate read from PEM file
 * @param {Buffer} rawIssuer issuer certificate read from PEM file
 * @return {Object} Object holding OCSP request information.
 */
const generateOCSPRequest = async (rawCert, rawIssuer) => {
  let cert;
  if (rawCert.tbsCertificate) {
    cert = rawCert;
  } else {
    cert = rfc5280.Certificate.decode(toDER(rawCert, 'CERTIFICATE'), 'der');
  }
  let issuer;
  if (rawIssuer.tbsCertificate) {
    issuer = rawIssuer;
  } else {
    issuer = rfc5280.Certificate.decode(toDER(rawIssuer, 'CERTIFICATE'), 'der');
  }
  let tbsCert = cert.tbsCertificate;
  let tbsIssuer = issuer.tbsCertificate;
  let certID = {
    hashAlgorithm: {
      // algorithm: [ 2, 16, 840, 1, 101, 3, 4, 2, 1 ]  // sha256
      algorithm: [1, 3, 14, 3, 2, 26] // sha1
    },
    issuerNameHash: await sha1(rfc5280.Name.encode(tbsCert.issuer, 'der').buffer),
    issuerKeyHash: await sha1(tbsIssuer.subjectPublicKeyInfo.subjectPublicKey.data.buffer),
    serialNumber: tbsCert.serialNumber
  };
  let randByteArray = new Uint32Array(16);
  randByteArray = crypto.getRandomValues(randByteArray);
  const randByteBuffer = Buffer.from(randByteArray);
  let tbs = {
    version: 'v1',
    requestList: [
      {
        reqCert: certID
      }
    ],
    requestExtensions: [
      {
        extnID: rfc2560['id-pkix-ocsp-nonce'],
        critical: false,
        extnValue: rfc2560.Nonce.encode(randByteBuffer, 'der')
      }
    ]
  };

  let req = {
    tbsRequest: tbs
  };

  return {
    id: await sha1(rfc2560.CertID.encode(certID, 'der')),
    certID: certID,
    data: rfc2560.OCSPRequest.encode(req, 'der'),

    // Just to avoid re-parsing DER
    cert: cert,
    issuer: issuer
  };
};

/**
 * Adaptation of ocsp.getAuthorityInfo (from ocsp library) that does NOT use callbacks.
 * @param {Buffer} cert PEM encoded certificate
 * @param {Buffer} key Key that can be used to locate OCSP server URI
 * @return {string} OCSP server URI
 */
const getOCSPAuthorityInfo = (cert, key) => {
  let exts = cert.tbsCertificate.extensions;
  if (!exts) exts = [];

  let infoAccess = exts.filter(ext => {
    return ext.extnID === 'authorityInformationAccess';
  });

  if (infoAccess.length === 0) return new Error('AuthorityInfoAccess not found in extensions');

  let res = null;
  let found = infoAccess.some(info => {
    let ext = info.extnValue;
    return ext.some(ad => {
      if (ad.accessMethod.join('.') !== key) return false;

      let loc = ad.accessLocation;
      if (loc.type !== 'uniformResourceIdentifier') return false;
      res = loc.value + '';
      return true;
    });
  });

  if (!found) throw new Error(key + ' not found in AuthorityInfoAccess');

  return res;
};

/**
 * Adaptation of ocsp.check (from ocsp library) that does NOT verify signatures in OCSP responses and
 * uses fetch-provided promises instead of http.request callbacks.
 * @param {string} uri URI of ocsp responder
 * @param {Buffer} req_data DER-encoded OCSP request
 * @return {Promise} Promise for http request, from which the OCSP response can be read.
 */
const getOCSPResponse = async (uri, req_data) => {
  uri = new URL(uri);

  return await fetch(uri.href, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/ocsp-request',
      'Content-Length': req_data.length
    },
    body: req_data
  }).then(response => {
    return response.arrayBuffer();
  });
};

const staple = async (cert, issuerCert) => {
  let req = null;
  try {
    req = await generateOCSPRequest(cert, issuerCert);
  } catch (e) {
    return new Error(e);
  }

  const ocspMethod = rfc2560['id-pkix-ocsp'].join('.');
  const uri = getOCSPAuthorityInfo(req.cert, ocspMethod);
  const response = await getOCSPResponse(uri, req.data);
  return Buffer.from(response);
};

const parseCertChain = filename => {
  const regex = /^(-{5}BEGIN CERTIFICATE-{5}\s+[^-]+-{5}END CERTIFICATE-{5})/gm;
  let fileContents = fs.readFileSync(filename).toString();
  let certs = [];
  let m;

  while ((m = regex.exec(fileContents)) !== null) {
    // This is necessary to avoid infinite loops with zero-width matches
    if (m.index === regex.lastIndex) {
      regex.lastIndex++;
    }

    // The result can be accessed through the `m`-variable.
    m.forEach((match, groupIndex) => {
      // console.log(`Found match, group ${groupIndex}: ${match}`);
      certs.push(match);
    });
  }
  return certs;
};

const fetchOCSP = async certs => {
  // Right now, the following code only handles chains where the 0th cert is the
  // actual cert to OCSP verify and the 1st cert is the CA cert.
  // This should cover most cases (unless we're handling chains with intermediate authorities)
  for (var i = 0; i < certs.length; i++) {
    const cert = certs[i];
    if (i === 0) {
      const issuerCert = certs[i + 1];
      let responseBytes = await staple(cert, issuerCert);
      console.log('OCSP response size is ' + responseBytes.length + ' bytes');
    }
  }
};

// Code that reads certchain input and formats it into OCSP request.
// First, read certificate chain file, which is in index two during invocation
// (node ocspFetch.js <certchain-file>)
let filename = process.argv[2];
let certs = parseCertChain(filename);

fetchOCSP(certs);
