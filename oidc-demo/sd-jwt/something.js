// generate_keys.js
import { ES256 } from '@sd-jwt/crypto-nodejs'
import * as crypto from 'crypto'
import fs from 'fs';

const generateKeyPair = async () => {

    const { privateKey, publicKey } = await ES256.generateKeyPair();

  // Save keys to files
  fs.writeFileSync('privateKey.json', JSON.stringify(privateKey, null, 2));
  fs.writeFileSync('publicKey.json', JSON.stringify(publicKey, null, 2));
  
  console.log('Key pair generated and saved as privateKey.json and publicKey.json');
};

generateKeyPair();
