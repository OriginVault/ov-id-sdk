import { MemoryDIDStore } from '@veramo/did-manager';
import { storePrivateKey, retrievePrivateKey } from './storePrivateKeys.js';

export class InMemoryKeyStore extends MemoryDIDStore {
    async importKey(args: { alias?: string; privateKeyHex: string }): Promise<any> {
        const key = { ...args, kid: args.alias || Math.random().toString() };
        await storePrivateKey(key.kid, args.privateKeyHex);
        return key;
    }

    async getKey({ alias }: { alias: string }): Promise<any> {
        const privateKeyHex = await retrievePrivateKey(alias);
        if (!privateKeyHex) throw Error(`Key not found: ${alias}`);
        return {
            kid: alias,
            alias,
            privateKeyHex,
            type: 'Ed25519',
            kms: 'local'
        };
    }

    async deleteKey({ alias }: { alias: string }): Promise<boolean> {
        const key = await retrievePrivateKey(alias);
        if (!key) return false;
        await storePrivateKey(alias, ''); // Clear the key
        return true;
    }

    async listKeys(): Promise<any[]> {
        // Note: This implementation is limited as the Map isn't exposed
        // You might want to add a method to list all keys in storePrivateKeys.ts
        return [];
    }
} 