import { agent } from './veramoAgent.js';

export async function resolveDID(did: string): Promise<any> {
    try {
        const resolvedDid = await agent.resolveDid({ didUrl: did });
        return resolvedDid;
    } catch (error) {
        console.error("❌ Error resolving DID:", error);
        throw error;
    }
} 