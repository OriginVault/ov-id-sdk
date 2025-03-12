import { DIDResolutionResult } from '@originvault/ov-types';
import { userAgent } from './userAgent.js';

export async function resolveDID(did: string): Promise<DIDResolutionResult> {
    try {
        const resolvedDid = await userAgent?.resolveDid({ didUrl: did });
        return resolvedDid as DIDResolutionResult;
    } catch (error) {
        console.error("❌ Error resolving DID:", error);
        throw error;
    }
} 