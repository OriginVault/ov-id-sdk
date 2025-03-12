import { userAgent } from './userAgent.js';
import { verifyPrimaryDID } from './identityManager.js';

export async function signVC(subject: any, password): Promise<any> {
    try {
        const did = await verifyPrimaryDID(password);

        if(typeof did !== 'string') return false;

        const signedVC = await userAgent?.createVerifiableCredential({
            credential: {
                issuer: { id: did },
                credentialSubject: {
                    id: did,
                    ...subject
                },
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                type: ['VerifiableCredential'],
            },
            proofFormat: 'jwt'
        })
        return signedVC;
    } catch (error) {
        console.error("❌ Error signing VC:", error);
        throw error;
    }
}

export async function verifyVC(credential: any): Promise<any> {
    try {
        const verified = await userAgent?.verifyCredential({
            credential,
            policies: { proofFormat: 'jwt' }
        });
        return verified;
    } catch (error) {
        console.error("❌ Error verifying VC:", error);
        throw error;
    }
} 