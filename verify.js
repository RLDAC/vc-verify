import fs from 'fs';
import {vc} from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {documentLoader} from './documentLoader.js';

const credential = JSON.parse(
  fs.readFileSync('./credential.json')
);

const result = await vc.verifyCredential({
  credential,
  documentLoader,
  suite: new DataIntegrityProof()
});

console.log(JSON.stringify(result, null, 2));
