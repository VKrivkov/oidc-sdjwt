// test_sdjwt.js
import { SDJwtInstance } from '@sd-jwt/core';
import { ES256, digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import fs from 'fs';

// Function to load JWK from file
const loadJwk = (filePath) => {
  const jwkData = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(jwkData);
};

(async () => {
    console.log('Debugging starts...');
    
    // Load the persisted key pair
    const privateJwk = loadJwk('privateKey.json');
    const publicJwk = loadJwk('publicKey.json');
    
    // Get signer and verifier using the persisted keys
    const signer = await ES256.getSigner(privateJwk);
    let verifier = await ES256.getVerifier(publicJwk);
    
    // Create SDJwt instance for signing and verifying
    const sdjwt = new SDJwtInstance({
        signer,
        verifier,
        signAlg: ES256.alg,
        hasher: digest,
        hashAlg: 'SHA-256',
        saltGenerator: generateSalt,
    });
    // Define the claims object with the user's information
    const claims = {
        firstname: 'John',
        lastname: 'Doe',
        ssn: '123-45-6789',
        id: '1234',
    };

    const disclosureFrame = {
        _sd: ['firstname', 'lastname', 'ssn'],
    };

    // Issue the SD-JWT
    const credential = await sdjwt.issue(claims, disclosureFrame, { header: {
        alg: 'ES256',
        typ: 'sd+jwt',
        jwk: publicJwk, // Add the public JWK to the header
    }});
    console.log('Encoded SD-JWT:', credential);


    const parts = credential.split('.'); // Split the JWT into parts
    const headerBase64 = parts[0]; // Header is the first part
    const headerJson = JSON.parse(atob(headerBase64)); // Decode base64 to JSON
    const publicJwk2 = headerJson.jwk; // Extract the JWK from the header

    if (!publicJwk2) {
        throw new Error('Public key (JWK) not found in the SD-JWT header.');
    }

    console.log(publicJwk2);

    // Create verifier using the extracted public key
    verifier = await ES256.getVerifier(publicJwk2);


    const sdjwt2 = new SDJwtInstance({
        verifier,
        signAlg: ES256.alg,
        hasher: digest,
        hashAlg: 'SHA-256',
        saltGenerator: generateSalt,
      });
      

    // Validate the SD-JWT
    const isValid = await sdjwt2.validate(credential);
    console.log('Valid? SD-JWT:', isValid);



    if (isValid) {
        // Decode the SD-JWT
        const sdJwtToken = await sdjwt2.decode(credential);
        console.log('Decoded Token:', JSON.stringify(sdJwtToken, null, 2));

        const keys = await sdJwtToken.keys(digest);
        console.log({ keys });

        const payloads = await sdJwtToken.getClaims(digest);

        const presentableKeys = await sdJwtToken.presentableKeys(digest);

        console.log({
            payloads: JSON.stringify(payloads, null, 2),
            disclosures: JSON.stringify(sdJwtToken.disclosures, null, 2),
            claim: JSON.stringify(sdJwtToken.jwt?.payload, null, 2),
            presentableKeys,
        });

        // Present the SD-JWT
        const presentationFrame = { firstname: true, id: true, ssn: true };
        const presentation = await sdjwt2.present(credential, presentationFrame);
        console.log('Presented SD-JWT:', presentation);



        const parts = presentation.split('.'); // Split the JWT into parts
        const headerBase64 = parts[0]; // Header is the first part
        const headerJson = JSON.parse(atob(headerBase64)); // Decode base64 to JSON
        const publicJwk3 = headerJson.jwk; // Extract the JWK from the header
    
        if (!publicJwk3) {
            throw new Error('Public key (JWK) not found in the SD-JWT header.');
        }
    
        console.log(publicJwk3);
    
        // Create verifier using the extracted public key
        verifier = await ES256.getVerifier(publicJwk3);
    
    
        const sdjwt3 = new SDJwtInstance({
            verifier,
            signAlg: ES256.alg,
            hasher: digest,
            hashAlg: 'SHA-256',
            saltGenerator: generateSalt,
          });
      
          

        // Verify the presented SD-JWT
        const requiredClaims = ['firstname', 'ssn', 'id'];
        const verified = await sdjwt3.verify(presentation, requiredClaims);
        console.log('Verification Result:', verified);
    } else {
        console.error('Invalid SD-JWT. Cannot proceed with decoding.');
    }
})();
