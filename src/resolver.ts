import { userAgent } from './userAgent.js';

export async function resolveDID(did: string): Promise<any> {
    try {
        const resolvedDid = await userAgent.resolveDid({ didUrl: did });
        return resolvedDid;
    } catch (error) {
        console.error("❌ Error resolving DID:", error);
        throw error;
    }
} 