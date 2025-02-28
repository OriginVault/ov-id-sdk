import * as VeramoAgent from './veramoAgent.js';
import * as InMemoryKeyStore from './InMemoryKeyStore.js';
import * as Resolver from './resolver.js';
import * as Signer from './signer.js';
import * as StorePrivateKeys from './storePrivateKeys.js';
import * as IdentityManager from './identityManager.js'; 

export * from './veramoAgent.js';
export * from './InMemoryKeyStore.js';
export * from './resolver.js';
export * from './signer.js';
export * from './storePrivateKeys.js';
export * from './identityManager.js'; 

export const OvId = {
    agent: VeramoAgent,
    memoryStore: InMemoryKeyStore,
    resolver: Resolver,
    signer: Signer,
    storePrivateKeys: StorePrivateKeys,
    identityManager: IdentityManager
}
