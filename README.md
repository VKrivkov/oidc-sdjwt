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

