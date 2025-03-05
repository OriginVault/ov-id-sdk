import { agent } from './veramoAgent.js';
import { verifyPrimaryDID } from './identityManager.js';
import { getDevelopmentEnvironmentMetadata, getProductionEnvironmentMetadata } from './environment.js';

export async function signVC(subject: any, password): Promise<any> {
    try {
        console.log("🔑 Signing VC", subject);
        const did = await verifyPrimaryDID(password);

        if(!did) return false;

        const environment = process.env.NODE_ENV === 'development' ? 
            await getDevelopmentEnvironmentMetadata() : 
            await getProductionEnvironmentMetadata();

        const signedVC = await agent.createVerifiableCredential({
            credential: {
                issuer: { id: did },
                credentialSubject: {
                    id: did,
                    environment,
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