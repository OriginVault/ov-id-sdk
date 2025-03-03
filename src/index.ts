import * as VeramoAgent from './veramoAgent.js';
import * as Resolver from './resolver.js';
import * as Signer from './signer.js';
import * as StorePrivateKeys from './storePrivateKeys.js';
import * as IdentityManager from './identityManager.js'; 
import * as Encryption from './encryption.js';
import * as Environment from './environment.js';
import * as ReleaseManager from './releaseManager.js';

export * from './veramoAgent.js';
export * from './resolver.js';
export * from './signer.js';
export * from './storePrivateKeys.js';
export * from './identityManager.js';
export * from './encryption.js';
export * from './environment.js';
export * from './releaseManager.js';

export const OvId = {
    agent: VeramoAgent,
    resolver: Resolver,
    signer: Signer,
    storePrivateKeys: StorePrivateKeys,
    identityManager: IdentityManager,
    encryption: Encryption,
    environment: Environment,
    releaseManager: ReleaseManager,
}

