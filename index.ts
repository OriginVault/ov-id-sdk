import * as UserAgent from './src/userAgent.js';
import * as Resolver from './src/resolver.js';
import * as Signer from './src/signer.js';
import * as StorePrivateKeys from './src/storePrivateKeys.js';
import * as IdentityManager from './src/identityManager.js'; 
import * as Encryption from './src/encryption.js';
import * as Environment from './src/environment.js';
import * as WalletManager from './src/walletManager.js';
import * as PackageAgent from './src/packageAgent.js';
import * as PackageManager from './src/packageManager.js';
import * as ResourceManager from './src/resourceManager.js';
import * as ParentAgent from './src/parentAgent.js';

export * from './src/userAgent.js';
export * from './src/resolver.js';
export * from './src/signer.js';
export * from './src/storePrivateKeys.js';
export * from './src/identityManager.js';
export * from './src/encryption.js';
export * from './src/environment.js';
export * from './src/walletManager.js';
export * from './src/packageAgent.js';
export * from './src/packageManager.js';
export * from './src/resourceManager.js';
export * from './src/parentAgent.js';

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

