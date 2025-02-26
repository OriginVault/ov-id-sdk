import { agent } from './veramoAgent.js';

export async function signVC(did: string, subject: any) {
  try {
    const signedVC = await agent.createVerifiableCredential({
      credential: {
        issuer: { id: did },
        credentialSubject: subject,
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        issuanceDate: new Date().toISOString(),
      },
      proofFormat: 'jwt'
    });
    return signedVC;
  } catch (error) {
    console.error("❌ Error signing VC:", error);
    throw error;
  }
}

export async function verifyVC(credential: any) {
  try {
    const verified = await agent.verifyCredential({
      credential,
      policies: { proofFormat: 'jwt' }
    });
    return verified;
  } catch (error) {
    console.error("❌ Error verifying VC:", error);
    throw error;
  }
} 