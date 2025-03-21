## Change Log

## v0.0.13
- [feat]: Tests `createDIDLinkedExecutable` function.
- [chore]: Upgrades `@cheqd/did-provider-cheqd` to v4.5.2.


## v0.0.12
 - [fix]: Fixes `privateKeyStore` imports from specific agents.

## v0.0.11
- [feat]: Adds `createDID` and `importDID` functions to the package.
- [feat]: Adds `sample.env` file to the package.
- [feat]: Adds `generate-multibase-key` script to generate a multibase key appropriately.
- [feat]: Adds `testnet` support to the package.

## v0.0.10
- [fix]: Fixes `getDID` to return `undefined` if the DID is not found in the keyring.
- [fix]: Fixes keyring encoding
- [fix]: Fixes `convertPrivateKeyToRecovery` to handle both 64 and 32 byte private keys.
- [fix]: Adds `retrieveKeys` to return keyring metadata

## v0.0.9
- [feat]: Adds `createDID` and `importDID` functions to the package.
- [fix]: Fixes `parentAgent` to be exported from the package.

## v0.0.8
- [fix]: Fixes imports in `parentAgent.ts`.

## v0.0.7
- [fix]: Fixes imports in `releaseManager.ts`.

## v0.0.6
- [fix]: Exports `releaseManager` from the package.

## v0.0.5
- [feat]: Adds `signRelease` function to sign the release metadata.

## v0.0.4
- [chore]: Update `ov-types` to v0.0.6
- [fix]: Fixed `userAgent.ts` and `resourceManager.ts` to use the new `IOVAgent` type.
- [fix]: `walletManeger.ts` had a bug that prevented it from being used.

## v0.0.3 
- [chore]: Update `ov-types` to v0.0.5

## v0.0.2
- [feat]: Introduces 3 main agents, `UserAgent`, `PackageAgent`, and `ParentAgent` each with their own stores.
- [feat]: Adds `ov-types` as a dependency.
- [feat]: Resource manager and publish/working directory key publication on Cheqd.
- [feat]: `OVId` class to manage decentralized identities (DIDs) and verifiable credentials (VCs).

## v0.0.1
- [feat]: Introduces package functionality.