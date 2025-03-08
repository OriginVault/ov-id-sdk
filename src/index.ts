import * as UserAgent from './userAgent.js';
import * as Resolver from './resolver.js';
import * as Signer from './signer.js';
import * as StorePrivateKeys from './storePrivateKeys.js';
import * as IdentityManager from './identityManager.js'; 
import * as Encryption from './encryption.js';
import * as Environment from './environment.js';
import * as WalletManager from './walletManager.js';
import * as PackageAgent from './packageAgent.js';
import * as PackageManager from './packageManager.js';
import * as ResourceManager from './resourceManager.js';
import * as ParentAgent from './parentAgent.js';

export * from './userAgent.js';
export * from './resolver.js';
export * from './signer.js';
export * from './storePrivateKeys.js';
export * from './identityManager.js';
export * from './encryption.js';
export * from './environment.js';
export * from './walletManager.js';
export * from './packageAgent.js';
export * from './packageManager.js';
export * from './resourceManager.js';
export * from './parentAgent.js';

export const OvId = {
    userAgent: UserAgent,
    resolver: Resolver,
    signer: Signer,
    storePrivateKeys: StorePrivateKeys,
    identityManager: IdentityManager,
    encryption: Encryption,
    environment: Environment,
    walletManager: WalletManager,
    packageAgent: PackageAgent,
    packageManager: PackageManager,
    resourceManager: ResourceManager,
    parentAgent: ParentAgent,
}

