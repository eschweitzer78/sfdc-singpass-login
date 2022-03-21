const express = require('express');
const jose = require('node-jose');
const { verify } = require('jsonwebtoken');
const jwksClient = require('jwks-client');

const {
    DecryptDataError,
    InvalidTokenSignatureError,
    MissingAccessTokenError,
    MissingParamsError,
    MyInfoResponseError,
    WrongDataShapeError,
    WrongAccessTokenShapeError,
    InvalidDataSignatureError,
} = require('./errors');

// TODO: change for production
const SINGPASS_WELL_KNOWN_ENDPOINT = 'https://stg-id.singpass.gov.sg/.well-known/keys';

/**
  * ===============================================
  * Tested with SingPass Login 0.1 and MyInfo 3.2.0
  * ===============================================
  */

const jwksClient = jwksClient({
    strictSsl: true, // Default value
    jwksUri: SINGPASS_WELL_KNOWN_ENDPOINT
});



/** 
  * ------------------------------------------
  * SIGNING LOGIN JWT FOR LOGIN 0.1
  * Used for Tokend endpoint - Auth Code Grant
  * in Login 0.1 documentation:
  * 4.1. Authorization Code Grant
  * 4.1.2. Authorization Code Grant - Authenticated with Client Assertion JWT
  * ------------------------------------------
  */


// TODO: Your private SingPass EC512 key
const pkcs8 = 
`-----BEGIN PRIVATE KEY-----
BYOK
-----END PRIVATE KEY-----`


let app = express();

app.use(express.json());

app.post('/signloginjwt', async (req, res, next) => {
    console.log('body=', req.body);
    let jwt = req.body['jwt'] ? req.body['jwt'] : null;
    let alg = req.body['alg'] ? req.body['alg'] : null;
    let kid = req.body['kid'] ? req.body['kid'] : null;

    // TODO change your key details, read from somwhere else
    const privateKey = await jose.JWK.asKey({
        'kty': 'EC',
        'd': 'your-d',
        'use': 'sig',
        'crv': 'P-521',
        'kid': 'your-kid-sig',
        'x': 'your-x',
        'y': 'your-y',
        'alg': 'ES512'
    });

    const encoder = new TextEncoder();
    const jws = await jose.JWS.
        createSign({ format: 'compact', alg: alg, fields: { typ: 'JWT', kid: kid }}, privateKey)
        .update(encoder.encode(jwt))
        .final();
 
    try {
        res.status(200);
        res.send({ status: 'OK', jws: jws });
    } catch (err) {
        res.status(200);
        res.send({ status: 'KO', error: err.message });
        next(err);
    }
});


/** 
  * ------------------------------------------
  * DECODE LOGIN JWE FOR LOGIN 0.1
  * Used for Tokend endpoint - Auth Code Grant
  * in Login 0.1 documentation:
  * 4.1. Authorization Code Grant
  * 4.1.3. ID Token Structure
  * 
  * Depending on the Client (Service Provider)
  * profile, the ID Token structure might be a
  * JWS [direct client profile] or JWS within
  * a JWE [direct_pii_allowed client profile].
  * Here illustrated for JWS within JWE.
  * ------------------------------------------
  */

app.post('/decodeloginjwe', async (req, res, next) => {
    let body = req.body['body'] ? req.body['body'] : null;

    try {
        let r = await decryptJWE(body, pkcs8, "publicSingpassSigningKey");
        res.status(200);
        res.send({ status: 'OK', body: r });
    } catch (err) {
        res.status(200);
        res.send({ status: 'KO', error: err.message });
        next(err);
    }
});



/** 
  * ---------------------------------------
  * DECRYPTING PERSON BODY FOR MYINFO 3.2.0
  * Used for Token Validation as described
  * in MyInfo 3.2.0 documentation:
  * Payload Signing and Encryption (Person)
  * ---------------------------------------
  */


// TODO: Service Provider's (Your) Private MyInfo RSA256 key
const pkcs8_sfdcsg = 
`-----BEGIN PRIVATE KEY-----
BYOK
-----END PRIVATE KEY-----`

// MyInfo public key
const x509_pubmyinfo = 
`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsGBNIs4nsiHNfLqoR40h
06We1IvWVaGISvETHKlJATWIURd9wx1bqHZ6tesVmLYqKT776kgxXwVD8NP0Vu+T
h8C+IF+9fMNOa8/TeowvcqDiIRjL7RId8kmpcmjtIS2G+MolfSbH7CRWVRko4q88
LMbJUAlglSnFppfQhsEVYlwLtZlHAYy9cl8PcsxPmFUzCUH4Fefyq77BBUPMpzbZ
LLjlAj97rF1oSQJKHM6RBLcvI+AauRpKe34O3GR9bCCTbkhETVerWsemtFUznr9m
oOSaDkEMIGA5wDyt12kjKKvbbm+k2Y5TMq1IIQXfhihGAbTttVpmZLYwJda0nemL
4QIDAQAB
-----END PUBLIC KEY-----`;


app.post('/decodepersonbody', async (req, res, next) => {
    let body = req.body['body'] ? req.body['body'] : null;

    try {
        let r = await decryptJWE(body, pkcs8_sfdcsg, x509_pubmyinfo);

        res.status(200);
        res.send({ status: 'OK', body: r });
    } catch (err) {
        res.status(200);
        res.send({ status: 'KO', error: err.message });
        next(err);
    }
});



/**
  * ----------------------
  * Utility
  * JWE Decryption 
  * ----------------------
  */


/**
  * Decrypts a JWE response string.
  * @param jwe Fullstop-delimited JWE
  * @returns The decrypted data, with signature already verified
  * @throws {DecryptDataError} Throws if an error occurs while decrypting data
  * @throws {InvalidDataSignatureError} Throws if signature on data is invalid
  * @throws {WrongDataShapeError} Throws if decrypted data from MyInfo is
  * of the wrong type
  */
 async function decryptJWE(jwe, privateKeyPemString, signaturePublicKeyPemString) {
    let jwt;
    let decoded;

    try {
        const privateKey = await jose.JWK.asKey(privateKeyPemString, 'pem');
        const { payload } = await jose.JWE.createDecrypt(privateKey).decrypt(jwe);
        jwt = JSON.parse(payload.toString());
    } catch (err) {
        throw new DecryptDataError(err);
    }

    try {
        decoded = verify(jwt, signaturePublicKeyPemString, { algorithms: ['RS256'] });
    } catch (err) {
        throw new InvalidDataSignatureError(err);
    }

    if (typeof decoded !== 'object') {
        throw new WrongDataShapeError();
    }

    return decoded;
}

let port = process.env.PORT || 3000;
app.listen(port);
console.log('Express started on port ' + port);
