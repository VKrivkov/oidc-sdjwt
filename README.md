# OIDC-SDJWT Demo

## Overview
This repository demonstrates an OpenID Connect (OIDC) identity provider (IdP) and relying party (RP) setup that incorporates **Selective Disclosure JSON Web Tokens (SD-JWT)**. It allows secure authentication and selective disclosure of user claims.

The implementation includes:
- An **Identity Provider (IdP)** server using `oidc-provider`.
- A **Relying Party (RP)** client using `openid-client`.
- Custom grant type for **Selective Disclosure**.
- Secure key management for signing and verifying JWTs.
- Example views for login, consent, and profile pages.

### File Structure
```
.
├── oidc-demo
│   ├── grants
│   │   ├── pjwks.json          # Public JWK Set for verification
│   │   ├── privateKey.json     # EC Private Key
│   │   ├── publicKey.json      # EC Public Key
│   │   ├── selectiveDisclosureGrant.js # Custom grant handler
│   ├── sd-jwt
│   │   ├── key-utils.js        # Utility for key operations
│   │   ├── generate-keys.js    # Script to generate key pairs
│   │   ├── test-sdjwt.js       # Test script for SD-JWT
│   │   ├── adapter.js          # Custom adapter for storage
│   │   ├── idp.js              # Identity Provider configuration
│   ├── node_modules           # Dependencies
│   ├── package.json           # Project configuration
│
├── rp-demo
│   ├── app.js                 # Relying Party application
│   ├── sd-utils.js            # SD-JWT Utilities for RP
│   ├── cert.pem               # SSL certificate
│   ├── key.pem                # SSL private key
│
├── views
│   ├── consent.ejs            # Consent page
│   ├── login.ejs              # Login page
```


## Key Features
- **Selective Disclosure JWT (SD-JWT):** Enable fine-grained control over which claims are shared.
- **Custom Grant Type:** Implements a custom OIDC grant for selective disclosure.
- **Secure Key Management:** Uses EC and RSA key pairs for signing and verification.
- **OIDC Flows:** Standard OAuth 2.0 authorization code flow.
- **Secure Storage:** Implements an in-memory adapter for demonstration purposes.

## Dependencies
The project relies on the following key dependencies:

### oidc-demo
- `oidc-provider`: OpenID Connect provider library.
- `@sd-jwt/core`: Core library for SD-JWT handling.
- `@sd-jwt/crypto-nodejs`: Cryptographic utilities for SD-JWT.
- `jsonwebtoken`: Library for JWT signing and verification.
- `jwk-to-pem`: Convert JWK to PEM format.
- `express`: Web server framework.
- `helmet`: Security middleware for HTTP headers.
- `quick-lru`: In-memory storage.

### rp-demo
- `openid-client`: OpenID Connect Relying Party library.
- `express`: Web server framework.
- `session`: Session management.
- `https`: Secure server handling.

### License

This project is licensed under the **MIT License**.


### Logs

**Server** (idp.js)

```
% node idp.js
OIDC Provider listening on port 4000
POST /interaction/:uid/login called with UID: Sy6GmOTB_sNr8G-U9aU67
Received POST data: [Object: null prototype] { username: 'alice', password: '123' }
Result data: { login: { accountId: 'user1' } }
Interaction Confirm Details: {
  uid: '1E8wl8hdrzOE26YAmlIJJ',
  prompt: {
    name: 'consent',
    reasons: [ 'op_scopes_missing' ],
    details: { missingOIDCScope: [Array] }
  },
  params: {
    client_id: 'client_app',
    code_challenge: 'wb0wXbvm7bLEB42IDUeClaIQr3DH517KUic6u8zopBE',
    code_challenge_method: 'S256',
    redirect_uri: 'https://localhost:3000/callback',
    response_type: 'code',
    scope: 'openid profile email',
    state: '5eJOITprsvi9v70YAk2I4x1p0bfHLzyFsw-UHpQI_Hs'
  },
  session: {
    accountId: 'user1',
    uid: 'x-LwyhTCevfhH64_zUcCq',
    cookie: 'Pjf8U_AZqb4KXTyPxQu69'
  }
}
Grant successfully saved, Result: { consent: { grantId: '68-UismmOVqyOdNQX8ZbaE2gT47Lvh4QLppjs9eTBz1' } }
Decoded original_jwt: {
  sub: 'user1',
  at_hash: 'No09-JTI8TrmIHHke3LqnQ',
  aud: 'client_app',
  exp: 1736255971,
  iat: 1736252371,
  iss: 'https://localhost:4000'
}
Issued SD-JWT with Public Key: eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiIsImp3ayI6eyJrZXlfb3BzIjpbInZlcmlmeSJdLCJleHQiOnRydWUsImt0eSI6IkVDIiwieCI6IjRjbkZ3THJ4bE5QYnN4dVNPbWp3ckZrR0FhVUlhd29ST25GTHZReEZveVEiLCJ5IjoiTFFPdUFaQUtURUUwbl9XZDdfUE1XT2tXSWktc1FJWTdaaGdPVnRKOE9GayIsImNydiI6IlAtMjU2In19.eyJzZF9qd3RfcHVibGljX2tleSI6eyJrZXlfb3BzIjpbInZlcmlmeSJdLCJleHQiOnRydWUsImt0eSI6IkVDIiwieCI6IjRjbkZ3THJ4bE5QYnN4dVNPbWp3ckZrR0FhVUlhd29ST25GTHZReEZveVEiLCJ5IjoiTFFPdUFaQUtURUUwbl9XZDdfUE1XT2tXSWktc1FJWTdaaGdPVnRKOE9GayIsImNydiI6IlAtMjU2In0sIl9zZCI6WyJJWVdRYmU1eVowYUE2Vk5yQjc2aXJpRmFnOE90MjlMd0NwMTNQSEdqU01nIiwieVpabVRjWW5xcUdwX0ZBVVJKN2k0Vkl0ajVlWlRDU2JGUmwwOHVEYzRSbyJdLCJfc2RfYWxnIjoiU0hBLTI1NiJ9.QkGA6GqdMPSaUftxHgs1kG40ioP1GtzYggcIIPs0bThmlvwkWegrs0pFmsxJ2e5Y4yAqmPpVPmNfJFXQGeCDDA~WyIzMmU1NThjMzFlYjJmMzVkIiwibmFtZSIsIkFsaWNlIl0~WyIwNTNjN2MwNWFjY2EyYTE5IiwiZW1haWwiLCJhbGljZUBleGFtcGxlLmNvbSJd~
```

**Client** (app.js)

```
% NODE_TLS_REJECT_UNAUTHORIZED='0' node app.js
(node:78910) Warning: Setting the NODE_TLS_REJECT_UNAUTHORIZED environment variable to '0' makes TLS connections and HTTPS requests insecure by disabling certificate verification.
(Use `node --trace-warnings ...` to show where the warning was created)
Client app listening on port 3000
OIDC configuration discovered successfully.
Redirecting to authorization URL: https://localhost:4000/auth?redirect_uri=https%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid+profile+email&code_challenge=wb0wXbvm7bLEB42IDUeClaIQr3DH517KUic6u8zopBE&code_challenge_method=S256&state=5eJOITprsvi9v70YAk2I4x1p0bfHLzyFsw-UHpQI_Hs&client_id=client_app&response_type=code
Token Endpoint Response: {
  access_token: 'udS1g_ffHT9lEf-szlLnCH5IB3MnAqO_Fd2cdW6vuZX',
  expires_in: 3600,
  id_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9pZGMtcHJvdmlkZXIta2V5LTEifQ.eyJzdWIiOiJ1c2VyMSIsImF0X2hhc2giOiJObzA5LUpUSThUcm1JSEhrZTNMcW5RIiwiYXVkIjoiY2xpZW50X2FwcCIsImV4cCI6MTczNjI1NTk3MSwiaWF0IjoxNzM2MjUyMzcxLCJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo0MDAwIn0.1s5_b7x-zsTNMisRcJ8n8GaIayPCQMaEBhK1Lz27oWnttLNjVc8Xs5PCApAxQxAN2Fj81WxDgodgkOTa39a-6gN7JmQxbqmGraXFm4Ae-h17ruzIRE4PpnW56PlRPfZGgzCCAJ3xUAUhezsY0JRDzOkJSXYUMGjq8G3cKYtCgNqmgHXFPfrertdJnwJ-i9yOYzIZ2f-9lasMiBczDBkkT7mzAHnMsD07_H8NdcCRH2JNnFnkikGH7mMTyJRu3M_amZoW3bowbgfJ13ObYcChs7IdiT9tP7gOuEfqNNldHGH85URQn0fYL-kJa2tVHJZSeBWnDEz3mTrLcu0GI6Q1RA',
  scope: 'openid profile email',
  token_type: 'bearer'
}
Access Token: udS1g_ffHT9lEf-szlLnCH5IB3MnAqO_Fd2cdW6vuZX
ID Token Claims: {
  sub: 'user1',
  at_hash: 'No09-JTI8TrmIHHke3LqnQ',
  aud: 'client_app',
  exp: 1736255971,
  iat: 1736252371,
  iss: 'https://localhost:4000'
}
SD-JWT Response: {
  access_token: 'eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiIsImp3ayI6eyJrZXlfb3BzIjpbInZlcmlmeSJdLCJleHQiOnRydWUsImt0eSI6IkVDIiwieCI6IjRjbkZ3THJ4bE5QYnN4dVNPbWp3ckZrR0FhVUlhd29ST25GTHZReEZveVEiLCJ5IjoiTFFPdUFaQUtURUUwbl9XZDdfUE1XT2tXSWktc1FJWTdaaGdPVnRKOE9GayIsImNydiI6IlAtMjU2In19.eyJzZF9qd3RfcHVibGljX2tleSI6eyJrZXlfb3BzIjpbInZlcmlmeSJdLCJleHQiOnRydWUsImt0eSI6IkVDIiwieCI6IjRjbkZ3THJ4bE5QYnN4dVNPbWp3ckZrR0FhVUlhd29ST25GTHZReEZveVEiLCJ5IjoiTFFPdUFaQUtURUUwbl9XZDdfUE1XT2tXSWktc1FJWTdaaGdPVnRKOE9GayIsImNydiI6IlAtMjU2In0sIl9zZCI6WyJJWVdRYmU1eVowYUE2Vk5yQjc2aXJpRmFnOE90MjlMd0NwMTNQSEdqU01nIiwieVpabVRjWW5xcUdwX0ZBVVJKN2k0Vkl0ajVlWlRDU2JGUmwwOHVEYzRSbyJdLCJfc2RfYWxnIjoiU0hBLTI1NiJ9.QkGA6GqdMPSaUftxHgs1kG40ioP1GtzYggcIIPs0bThmlvwkWegrs0pFmsxJ2e5Y4yAqmPpVPmNfJFXQGeCDDA~WyIzMmU1NThjMzFlYjJmMzVkIiwibmFtZSIsIkFsaWNlIl0~WyIwNTNjN2MwNWFjY2EyYTE5IiwiZW1haWwiLCJhbGljZUBleGFtcGxlLmNvbSJd~',
  token_type: 'bearer',
  expires_in: 3600,
  scope: 'selective_disclosure'
}
{
  key_ops: [ 'verify' ],
  ext: true,
  kty: 'EC',
  x: '4cnFwLrxlNPbsxuSOmjwrFkGAaUIawoROnFLvQxFoyQ',
  y: 'LQOuAZAKTEE0n_Wd7_PMWOkWIi-sQIY7ZhgOVtJ8OFk',
  crv: 'P-256'
}
Valid? SD-JWT: {
  payload: {
    sd_jwt_public_key: {
      key_ops: [Array],
      ext: true,
      kty: 'EC',
      x: '4cnFwLrxlNPbsxuSOmjwrFkGAaUIawoROnFLvQxFoyQ',
      y: 'LQOuAZAKTEE0n_Wd7_PMWOkWIi-sQIY7ZhgOVtJ8OFk',
      crv: 'P-256'
    },
    name: 'Alice',
    email: 'alice@example.com'
  },
  header: {
    typ: 'sd+jwt',
    alg: 'ES256',
    jwk: {
      key_ops: [Array],
      ext: true,
      kty: 'EC',
      x: '4cnFwLrxlNPbsxuSOmjwrFkGAaUIawoROnFLvQxFoyQ',
      y: 'LQOuAZAKTEE0n_Wd7_PMWOkWIi-sQIY7ZhgOVtJ8OFk',
      crv: 'P-256'
    }
  }
}
Decoded Token: {
  "jwt": {
    "header": {
      "typ": "sd+jwt",
      "alg": "ES256",
      "jwk": {
        "key_ops": [
          "verify"
        ],
        "ext": true,
        "kty": "EC",
        "x": "4cnFwLrxlNPbsxuSOmjwrFkGAaUIawoROnFLvQxFoyQ",
        "y": "LQOuAZAKTEE0n_Wd7_PMWOkWIi-sQIY7ZhgOVtJ8OFk",
        "crv": "P-256"
      }
    },
    "payload": {
      "sd_jwt_public_key": {
        "key_ops": [
          "verify"
        ],
        "ext": true,
        "kty": "EC",
        "x": "4cnFwLrxlNPbsxuSOmjwrFkGAaUIawoROnFLvQxFoyQ",
        "y": "LQOuAZAKTEE0n_Wd7_PMWOkWIi-sQIY7ZhgOVtJ8OFk",
        "crv": "P-256"
      },
      "_sd": [
        "IYWQbe5yZ0aA6VNrB76iriFag8Ot29LwCp13PHGjSMg",
        "yZZmTcYnqqGp_FAURJ7i4VItj5eZTCSbFRl08uDc4Ro"
      ],
      "_sd_alg": "SHA-256"
    },
    "signature": "QkGA6GqdMPSaUftxHgs1kG40ioP1GtzYggcIIPs0bThmlvwkWegrs0pFmsxJ2e5Y4yAqmPpVPmNfJFXQGeCDDA",
    "encoded": "eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiIsImp3ayI6eyJrZXlfb3BzIjpbInZlcmlmeSJdLCJleHQiOnRydWUsImt0eSI6IkVDIiwieCI6IjRjbkZ3THJ4bE5QYnN4dVNPbWp3ckZrR0FhVUlhd29ST25GTHZReEZveVEiLCJ5IjoiTFFPdUFaQUtURUUwbl9XZDdfUE1XT2tXSWktc1FJWTdaaGdPVnRKOE9GayIsImNydiI6IlAtMjU2In19.eyJzZF9qd3RfcHVibGljX2tleSI6eyJrZXlfb3BzIjpbInZlcmlmeSJdLCJleHQiOnRydWUsImt0eSI6IkVDIiwieCI6IjRjbkZ3THJ4bE5QYnN4dVNPbWp3ckZrR0FhVUlhd29ST25GTHZReEZveVEiLCJ5IjoiTFFPdUFaQUtURUUwbl9XZDdfUE1XT2tXSWktc1FJWTdaaGdPVnRKOE9GayIsImNydiI6IlAtMjU2In0sIl9zZCI6WyJJWVdRYmU1eVowYUE2Vk5yQjc2aXJpRmFnOE90MjlMd0NwMTNQSEdqU01nIiwieVpabVRjWW5xcUdwX0ZBVVJKN2k0Vkl0ajVlWlRDU2JGUmwwOHVEYzRSbyJdLCJfc2RfYWxnIjoiU0hBLTI1NiJ9.QkGA6GqdMPSaUftxHgs1kG40ioP1GtzYggcIIPs0bThmlvwkWegrs0pFmsxJ2e5Y4yAqmPpVPmNfJFXQGeCDDA"
  },
  "disclosures": [
    {
      "_digest": "IYWQbe5yZ0aA6VNrB76iriFag8Ot29LwCp13PHGjSMg",
      "_encoded": "WyIzMmU1NThjMzFlYjJmMzVkIiwibmFtZSIsIkFsaWNlIl0",
      "salt": "32e558c31eb2f35d",
      "key": "name",
      "value": "Alice"
    },
    {
      "_digest": "yZZmTcYnqqGp_FAURJ7i4VItj5eZTCSbFRl08uDc4Ro",
      "_encoded": "WyIwNTNjN2MwNWFjY2EyYTE5IiwiZW1haWwiLCJhbGljZUBleGFtcGxlLmNvbSJd",
      "salt": "053c7c05acca2a19",
      "key": "email",
      "value": "alice@example.com"
    }
  ]
}
{
  keys: [
    'email',
    'name',
    'sd_jwt_public_key',
    'sd_jwt_public_key.crv',
    'sd_jwt_public_key.ext',
    'sd_jwt_public_key.key_ops',
    'sd_jwt_public_key.key_ops.0',
    'sd_jwt_public_key.kty',
    'sd_jwt_public_key.x',
    'sd_jwt_public_key.y'
  ]
}
{
  payloads: '{\n' +
    '  "sd_jwt_public_key": {\n' +
    '    "key_ops": [\n' +
    '      "verify"\n' +
    '    ],\n' +
    '    "ext": true,\n' +
    '    "kty": "EC",\n' +
    '    "x": "4cnFwLrxlNPbsxuSOmjwrFkGAaUIawoROnFLvQxFoyQ",\n' +
    '    "y": "LQOuAZAKTEE0n_Wd7_PMWOkWIi-sQIY7ZhgOVtJ8OFk",\n' +
    '    "crv": "P-256"\n' +
    '  },\n' +
    '  "name": "Alice",\n' +
    '  "email": "alice@example.com"\n' +
    '}',
  disclosures: '[\n' +
    '  {\n' +
    '    "_digest": "IYWQbe5yZ0aA6VNrB76iriFag8Ot29LwCp13PHGjSMg",\n' +
    '    "_encoded": "WyIzMmU1NThjMzFlYjJmMzVkIiwibmFtZSIsIkFsaWNlIl0",\n' +
    '    "salt": "32e558c31eb2f35d",\n' +
    '    "key": "name",\n' +
    '    "value": "Alice"\n' +
    '  },\n' +
    '  {\n' +
    '    "_digest": "yZZmTcYnqqGp_FAURJ7i4VItj5eZTCSbFRl08uDc4Ro",\n' +
    '    "_encoded": "WyIwNTNjN2MwNWFjY2EyYTE5IiwiZW1haWwiLCJhbGljZUBleGFtcGxlLmNvbSJd",\n' +
    '    "salt": "053c7c05acca2a19",\n' +
    '    "key": "email",\n' +
    '    "value": "alice@example.com"\n' +
    '  }\n' +
    ']',
  claim: '{\n' +
    '  "sd_jwt_public_key": {\n' +
    '    "key_ops": [\n' +
    '      "verify"\n' +
    '    ],\n' +
    '    "ext": true,\n' +
    '    "kty": "EC",\n' +
    '    "x": "4cnFwLrxlNPbsxuSOmjwrFkGAaUIawoROnFLvQxFoyQ",\n' +
    '    "y": "LQOuAZAKTEE0n_Wd7_PMWOkWIi-sQIY7ZhgOVtJ8OFk",\n' +
    '    "crv": "P-256"\n' +
    '  },\n' +
    '  "_sd": [\n' +
    '    "IYWQbe5yZ0aA6VNrB76iriFag8Ot29LwCp13PHGjSMg",\n' +
    '    "yZZmTcYnqqGp_FAURJ7i4VItj5eZTCSbFRl08uDc4Ro"\n' +
    '  ],\n' +
    '  "_sd_alg": "SHA-256"\n' +
    '}',
  presentableKeys: [ 'email', 'name' ]
}
Presented SD-JWT: eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiIsImp3ayI6eyJrZXlfb3BzIjpbInZlcmlmeSJdLCJleHQiOnRydWUsImt0eSI6IkVDIiwieCI6IjRjbkZ3THJ4bE5QYnN4dVNPbWp3ckZrR0FhVUlhd29ST25GTHZReEZveVEiLCJ5IjoiTFFPdUFaQUtURUUwbl9XZDdfUE1XT2tXSWktc1FJWTdaaGdPVnRKOE9GayIsImNydiI6IlAtMjU2In19.eyJzZF9qd3RfcHVibGljX2tleSI6eyJrZXlfb3BzIjpbInZlcmlmeSJdLCJleHQiOnRydWUsImt0eSI6IkVDIiwieCI6IjRjbkZ3THJ4bE5QYnN4dVNPbWp3ckZrR0FhVUlhd29ST25GTHZReEZveVEiLCJ5IjoiTFFPdUFaQUtURUUwbl9XZDdfUE1XT2tXSWktc1FJWTdaaGdPVnRKOE9GayIsImNydiI6IlAtMjU2In0sIl9zZCI6WyJJWVdRYmU1eVowYUE2Vk5yQjc2aXJpRmFnOE90MjlMd0NwMTNQSEdqU01nIiwieVpabVRjWW5xcUdwX0ZBVVJKN2k0Vkl0ajVlWlRDU2JGUmwwOHVEYzRSbyJdLCJfc2RfYWxnIjoiU0hBLTI1NiJ9.QkGA6GqdMPSaUftxHgs1kG40ioP1GtzYggcIIPs0bThmlvwkWegrs0pFmsxJ2e5Y4yAqmPpVPmNfJFXQGeCDDA~WyIzMmU1NThjMzFlYjJmMzVkIiwibmFtZSIsIkFsaWNlIl0~WyIwNTNjN2MwNWFjY2EyYTE5IiwiZW1haWwiLCJhbGljZUBleGFtcGxlLmNvbSJd~
Verification Result: {
  payload: {
    sd_jwt_public_key: {
      key_ops: [Array],
      ext: true,
      kty: 'EC',
      x: '4cnFwLrxlNPbsxuSOmjwrFkGAaUIawoROnFLvQxFoyQ',
      y: 'LQOuAZAKTEE0n_Wd7_PMWOkWIi-sQIY7ZhgOVtJ8OFk',
      crv: 'P-256'
    },
    name: 'Alice',
    email: 'alice@example.com'
  },
  header: {
    typ: 'sd+jwt',
    alg: 'ES256',
    jwk: {
      key_ops: [Array],
      ext: true,
      kty: 'EC',
      x: '4cnFwLrxlNPbsxuSOmjwrFkGAaUIawoROnFLvQxFoyQ',
      y: 'LQOuAZAKTEE0n_Wd7_PMWOkWIi-sQIY7ZhgOVtJ8OFk',
      crv: 'P-256'
    }
  }
}
```

