import { agent } from './veramoAgent.js';
import { generateMnemonic, mnemonicToSeedSync } from 'bip39';
import { storePrivateKey } from './storePrivateKeys.js';

export async function createDID(method: string): Promise<{ did: any; mnemonic: string }> {
    try {
        const mnemonic = generateMnemonic();
        const seed = mnemonicToSeedSync(mnemonic).toString('hex');
        const did = await agent.didManagerCreate({
            provider: `did:${method}`,
            alias: Date.now().toString()
        });
        await storePrivateKey(did.did, seed);
        return { did, mnemonic };
    } catch (error) {
        console.error("❌ Error creating DID:", error);
        throw error;
    }
}

export async function importDID(privateKeyHex: string, method: string, didString: string): Promise<any> {
    try {
        const did = await agent.didManagerImport({
            did: didString,
            keys: [{
                kid: 'default',
                type: 'Ed25519',
                kms: 'local',
                privateKeyHex: privateKeyHex,
            }],
            provider: `did:${method}`,
            alias: 'imported-did'
        });
        await storePrivateKey(didString, privateKeyHex);
        return did;
    } catch (error) {
        console.error("❌ Error importing DID:", error);
        throw error;
    }
} 