/**
 * Document Loader for JSON-LD processing
 * Resolves context URLs and DID documents
 */

import jsonld from 'jsonld';
import { Resolver } from 'did-resolver';
import { getResolver as getWebResolver } from 'web-did-resolver';

// Create DID resolver for did:web
const didResolver = new Resolver({
  ...getWebResolver()
});

// Cache for loaded documents
const documentCache = new Map();

// Known contexts
const CONTEXTS = {
  'https://www.w3.org/ns/credentials/v2': {
    '@context': {
      '@protected': true,
      'id': '@id',
      'type': '@type',
      'VerifiableCredential': {
        '@id': 'https://www.w3.org/2018/credentials#VerifiableCredential',
        '@context': {
          '@protected': true,
          'id': '@id',
          'type': '@type',
          'credentialSubject': {'@id': 'https://www.w3.org/2018/credentials#credentialSubject', '@type': '@id'},
          'issuer': {'@id': 'https://www.w3.org/2018/credentials#issuer', '@type': '@id'},
          'validFrom': {'@id': 'https://www.w3.org/2018/credentials#validFrom', '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'},
          'validUntil': {'@id': 'https://www.w3.org/2018/credentials#validUntil', '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'},
          'credentialStatus': {'@id': 'https://www.w3.org/2018/credentials#credentialStatus', '@type': '@id'}
        }
      },
      'credentialSubject': {'@id': 'https://www.w3.org/2018/credentials#credentialSubject', '@type': '@id'},
      'issuer': {'@id': 'https://www.w3.org/2018/credentials#issuer', '@type': '@id'},
      'proof': {'@id': 'https://w3id.org/security#proof', '@type': '@id', '@container': '@graph'}
    }
  },
  'https://www.w3.org/ns/credentials/v1': {
    '@context': {
      '@protected': true,
      'id': '@id',
      'type': '@type',
      'VerifiableCredential': 'https://www.w3.org/2018/credentials#VerifiableCredential',
      'credentialSubject': {'@id': 'https://www.w3.org/2018/credentials#credentialSubject', '@type': '@id'},
      'issuer': {'@id': 'https://www.w3.org/2018/credentials#issuer', '@type': '@id'},
      'issuanceDate': {'@id': 'https://www.w3.org/2018/credentials#issuanceDate', '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'},
      'expirationDate': {'@id': 'https://www.w3.org/2018/credentials#expirationDate', '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'},
      'credentialStatus': {'@id': 'https://www.w3.org/2018/credentials#credentialStatus', '@type': '@id'},
      'proof': {'@id': 'https://w3id.org/security#proof', '@type': '@id', '@container': '@graph'}
    }
  },
  'https://w3id.org/security/data-integrity/v2': {
    '@context': {
      '@protected': true,
      'id': '@id',
      'type': '@type',
      'DataIntegrityProof': 'https://w3id.org/security#DataIntegrityProof',
      'cryptosuite': 'https://w3id.org/security#cryptosuite',
      'proofPurpose': {'@id': 'https://w3id.org/security#proofPurpose', '@type': '@vocab'},
      'proofValue': 'https://w3id.org/security#proofValue',
      'verificationMethod': {'@id': 'https://w3id.org/security#verificationMethod', '@type': '@id'},
      'created': {'@id': 'http://purl.org/dc/terms/created', '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'},
      'assertionMethod': {'@id': 'https://w3id.org/security#assertionMethod', '@type': '@id', '@container': '@set'}
    }
  }
};

/**
 * Custom document loader for JSON-LD
 * @param {string} url - URL to load
 * @returns {Promise<object>} Loaded document
 */
export async function documentLoader(url) {
  // Check cache first
  if (documentCache.has(url)) {
    return documentCache.get(url);
  }

  // Check known contexts
  if (CONTEXTS[url]) {
    const result = {
      contextUrl: null,
      documentUrl: url,
      document: CONTEXTS[url]
    };
    documentCache.set(url, result);
    return result;
  }

  // Handle DID URLs
  if (url.startsWith('did:')) {
    const did = url.split('#')[0];
    try {
      const resolution = await didResolver.resolve(did);
      if (resolution.didDocument) {
        const result = {
          contextUrl: null,
          documentUrl: url,
          document: resolution.didDocument
        };
        documentCache.set(url, result);
        return result;
      }
    } catch (error) {
      throw new Error(`Failed to resolve DID: ${did} - ${error.message}`);
    }
  }

  // Fallback to default loader for HTTP(S) URLs
  try {
    const nodeLoader = jsonld.documentLoaders.node();
    const result = await nodeLoader(url);
    documentCache.set(url, result);
    return result;
  } catch (error) {
    throw new Error(`Failed to load document: ${url} - ${error.message}`);
  }
}

export default documentLoader;
