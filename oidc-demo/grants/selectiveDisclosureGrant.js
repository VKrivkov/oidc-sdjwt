// selectiveDisclosureGrant.js

import { SDJwtInstance } from '@sd-jwt/core';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import fs from 'fs';
import path from 'path';
import { InvalidRequest, InvalidGrant } from 'oidc-provider/lib/helpers/errors.js';
import jwt from 'jsonwebtoken'; // Import jsonwebtoken
import jwkToPem from 'jwk-to-pem'; // Import jwk-to-pem
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Function to load JWK from file
const loadJwk = (filePath) => {
  const jwkData = fs.readFileSync(path.join(__dirname, filePath), 'utf-8');
  return JSON.parse(jwkData);
};

// Simulated user database (should be consistent with idp.js)
const users = [
  {
    id: 'user1',
    username: 'alice',
    password: '123',
    name: 'Alice',
    email: 'alice@example.com',
  },
  {
    id: 'user2',
    username: 'bob',
    password: 'password456',
    name: 'Bob',
    email: 'bob@example.com',
  },
  // Add more users as needed
];

export async function selectiveDisclosureHandler(ctx, next) {
  try {
    const { claims_to_disclose, disclosure_scope, original_jwt } = ctx.oidc.params;

    // Step 1: Validate Parameters
    if (!claims_to_disclose) {
      throw new InvalidRequest('Missing required parameter: claims_to_disclose.');
    }
    if (!original_jwt) {
      throw new InvalidRequest('Missing required parameter: original_jwt.');
    }

    // Step 2: Validate and Decode original_jwt
    const rsaPublicJwk = loadJwk('pjwks.json'); //RSA public key for verifying original_jwt

    // Convert RSA JWK to PEM for jwt.verify
    const pem = jwkToPem(rsaPublicJwk);

    // Verify and decode the original JWT
    let decodedToken;
    try {
      decodedToken = jwt.verify(original_jwt, pem, { algorithms: ['RS256'] });
      console.log('Decoded original_jwt:', decodedToken);
    } catch (err) {
      console.error('Invalid original_jwt:', err);
      throw new InvalidGrant('Invalid original_jwt.');
    }

    const accountId = decodedToken.sub; // Assuming 'sub' claim holds the user ID
    const user = users.find((u) => u.id === accountId);
    if (!user) {
      throw new InvalidGrant('Invalid account.');
    }

    // Step 3: Validate Client Authorization for Claims
    const allowedClaims = ['name', 'email'];
    const requestedClaims = claims_to_disclose.split(',').map(c => c.trim());
    const validClaims = requestedClaims.filter(c => allowedClaims.includes(c));

    if (validClaims.length === 0) {
      throw new InvalidRequest('No valid claims to disclose were provided.');
    }

    // Step 4: Issue SD-JWT
    const ecPrivateJwk = loadJwk('privateKey.json'); // Path to your EC private key
    const ecPublicJwk = loadJwk('publicKey.json');   // Path to your EC public key

    const signer = await ES256.getSigner(ecPrivateJwk);

    const sdjwt = new SDJwtInstance({
      signer,
      signAlg: ES256.alg,
      hasher: digest,
      hashAlg: 'SHA-256',
      saltGenerator: generateSalt,
    });

    const disclosureFrame = { _sd: validClaims };
    const sdJwtPayload = {};

    validClaims.forEach(claim => {
      sdJwtPayload[claim] = user[claim];
    });

    // Embed the public key as a custom claim
    sdJwtPayload.sd_jwt_public_key = ecPublicJwk; // Adding the EC public key

    const sdJwt = await sdjwt.issue(sdJwtPayload, disclosureFrame, { header: {
      alg: 'ES256',
      typ: 'sd+jwt',
      jwk: ecPublicJwk, // Add the public JWK to the header
  }});


    console.log('Issued SD-JWT with Public Key:', sdJwt);

    // Step 5: Prepare the Token Response
    ctx.body = {
      access_token: sdJwt,
      token_type: 'Bearer',
      expires_in: 3600, // 1 hour
      scope: disclosure_scope || 'selective_disclosure',
    };
  } catch (error) {
    console.error('Selective Disclosure Grant Error:', error);
    // Set the response status and body appropriately
    ctx.status = error.status || 500;
    ctx.body = {
      error: error.message || 'server_error',
      error_description: error.description || 'An unknown error occurred.',
    };
  }

  await next();
}
