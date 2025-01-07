// sd-jwt-utils.js

import { SDJwtInstance } from '@sd-jwt/core';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';





// Initialize SDJwtInstance
const initializeSDJwt = async (token) => {

  const parts = token.split('.'); // Split the JWT into parts
  const headerBase64 = parts[0]; // Header is the first part
  const headerJson = JSON.parse(atob(headerBase64)); // Decode base64 to JSON
  const publicJwk = headerJson.jwk; // Extract the JWK from the header

  if (!publicJwk) {
      throw new Error('Public key (JWK) not found in the SD-JWT header.');
  }

  console.log(publicJwk);

    // Create verifier using the extracted public key
  const verifier = await ES256.getVerifier(publicJwk);

  const sdjwt = new SDJwtInstance({
    verifier,
    signAlg: ES256.alg,
    hasher: digest,
    hashAlg: 'SHA-256',
    saltGenerator: generateSalt,
  });

  return sdjwt;
};

export { initializeSDJwt };
