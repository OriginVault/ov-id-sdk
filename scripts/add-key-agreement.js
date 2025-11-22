import dotenv from 'dotenv';
import { packageStore } from '../src/packageAgent.js';

dotenv.config();
(async () => {
  const { agent, did, privateKeyStore } = await packageStore.initialize();

  try {
    // Generate a new X25519 key for key agreement
    const key = await agent.keyManagerCreate({
      type: 'X25519',
      kms: 'local',
    });

  // STEP 2: Resolve the existing DID document
  const resolved = await agent.resolveDid({ didUrl: did });
  const document = resolved.didDocument;

  // STEP 3: Add the keyAgreement section
  const verificationMethodId = `${did}#${key.kid}`;
  const newKeyAgreement = {
    id: verificationMethodId,
    type: 'X25519KeyAgreementKey2019',
    controller: did,
    publicKeyMultibase: key.publicKeyHex.startsWith('z') ? key.publicKeyHex : `z${key.publicKeyHex}`, // base58btc encoding
  };

  if (!document.keyAgreement) {
    document.keyAgreement = [];
  }
  if (!Array.isArray(document.keyAgreement)) {
    document.keyAgreement = [document.keyAgreement];
  }
  document.keyAgreement.push(verificationMethodId);

  if (!document.verificationMethod) {
    document.verificationMethod = [];
  }
  document.verificationMethod.push(newKeyAgreement);
  console.log({document, key, privateKeyStore});
//   // STEP 4: Perform the updateIdentifier call
//   const result = await agent.didManagerUpdate({
//     did,
//     document,
//     options: {
//       kms: 'local',
//       keys: [key],
//       versionId: uuidv4(),
//     },
//   });

  console.log('✅ Successfully updated DID with keyAgreement key');
  console.log('🔐 New key ID:', key.kid);
  } catch (error) {
    console.error(`❌ Error adding keyAgreement key to DID: ${error.message}`);
  }
})();