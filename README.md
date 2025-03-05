<div style="width: 100%; display: flex; justify-content: center; align-items: center;">
      <img src="https://gray-objective-tiglon-784.mypinata.cloud/ipfs/Qma7EjPPPfomzEKkYcJa2ctEFPUhHaMwiojTR1wTQPg2x8" alt="OriginVault logo" width="300" height="300">
</div>
<br />

# 🚀 `@originvault/ov-id-sdk` (in alpha)
**Decentralized Identity SDK for OriginVault**

`@originvault/ov-id-sdk` a TypeScript SDK for decentralized identity (DID) management, verifiable credential (VC) signing and verification, and cryptographic commit signing. It enables secure DID operations, private key management, W3C-compliant credential handling, and signed commits/releases with verifiable metadata.

🔹 Features

- ✅ DID Creation & Import → Generate or restore did:cheqd and did:vda identities
- ✅ Secure Key Storage → Encrypt and store private keys securely, retrieve when needed
- ✅ Primary DID Management → Set and retrieve the default DID for signing credentials
- ✅ Verifiable Credential Signing & Verification → Issue & verify W3C-compliant credentials
- ✅ Cryptographic Commit & Release Signing → Sign and verify Git commits & software releases using DID credentials
- ✅ Development Environment Metadata → Capture system & package metadata for auditability
- ✅ Domain-Linked DID Discovery → Auto-fetch the authoritative DID from .well-known/did-configuration.json
- ✅ Web5 Trust Layer Integration → Designed for OriginVault’s decentralized identity and verification ecosystem
---

## 📦 Installation
```bash
npm install @originvault/ov-id-sdk
```

## [Example Release Cert](https://github.com/OriginVault/ov-id-sdk/blob/main/.my-certificates/@originvault/ov-id-sdk-0.0.1-alpha.23-2025-03-03T05%EF%80%BA14%EF%80%BA01.454Z.json)



---

## 🚀 Quick Start

### **1️⃣ Create or Import a DID**
```typescript
import { createDID, importDID } from "@originvault/ov-id-sdk";

// ✅ Create a new DID
const { did } = await createDID("cheqd");
console.log("New DID:", did);

// ✅ Import an existing DID from a mnemonic
const importedDID = await importDID("your mnemonic phrase here", "cheqd");
console.log("Imported DID:", importedDID);
```

---

### **2️⃣ Securely Store & Retrieve a Private Key**
```typescript
import { storePrivateKey, retrievePrivateKey } from "@originvault/ov-id-sdk";

// ✅ Store a private key securely
await storePrivateKey("did:cheqd:mainnet:1234", "your-private-key");

// ✅ Retrieve the private key when needed
const privateKey = await retrievePrivateKey("did:cheqd:mainnet:1234");
console.log("Retrieved Private Key:", privateKey);
```

---

### **3️⃣ Set & Get a Primary DID for Signing**
```typescript
import { setPrimaryDID, getPrimaryDID } from "@originvault/ov-id-sdk";

// ✅ Set a primary DID
await setPrimaryDID("did:cheqd:mainnet:1234");

// ✅ Get the primary DID (for signing operations)
const primaryDID = await getPrimaryDID();
console.log("Primary DID:", primaryDID);
```

---

### **4️⃣ Sign & Verify Verifiable Credentials**
```typescript
import { signVC, verifyVC } from "@originvault/ov-id-sdk";

// ✅ Sign a Verifiable Credential
const vcJwt = await signVC("did:cheqd:mainnet:1234", "subject-id");
console.log("Signed VC:", vcJwt);

// ✅ Verify a Verifiable Credential
const isValid = await verifyVC(vcJwt);
console.log("VC Verification:", isValid);
```

---

### **5️⃣ Sign Commits and Releases**
```typescript
import { signLatestCommit, signCurrentRelease } from "@originvault/ov-id-sdk";

// ✅ Sign the latest commit
await signLatestCommit();
console.log("Latest commit signed successfully.");

// ✅ Sign the current release
await signCurrentRelease();
console.log("Current release signed successfully.");
```

---

### **6️⃣ Automatically Fetch Domain-Linked DID**
```typescript
import { getPrimaryDID } from "@originvault/ov-id-sdk";

// ✅ If no primary DID is set, check `.well-known/did-configuration.json` on the SDK's domain
process.env.SDK_DOMAIN = "example.com"; // Set the domain for validation
const domainDID = await getPrimaryDID();
console.log("Domain-Verified DID:", domainDID);
```

---

### **7️⃣ Get Development Environment Metadata**
```typescript
import { getDevelopmentEnvironmentMetadata } from "@originvault/ov-id-sdk";

const environment = getDevelopmentEnvironmentMetadata();
console.log("Development Environment:", environment);
```

## 🛠 Configuration
| **Environment Variable** | **Description** |
|------------------|-----------------------------------------------|
| `DID_DOMAIN` | (Optional) Domain to fetch `.well-known/did-configuration.json` |
| `DID_METHOD` | (Optional) Default DID method (`cheqd` or `vda`) |

---

## 🏗 Built With
- **[Cheqd DID SDK](https://docs.cheqd.io/)** → DID creation & verification  
- **[Veramo](https://veramo.io/)** → Web5-native identity agent  
- **[W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)** → Open trust standards  
- **[Polkadot Keyring](https://polkadot.js.org/docs/api/start/keyring/)** → Secure, in-memory key management for DIDs

---

## 📜 License
`@originvault/ov-id-sdk` is licensed under **MIT**.

---

## 🚀 Next Steps
- [ ] Add **multi-user key management**
- [ ] Support **additional DID methods**
- [ ] Provide **browser-compatible secure storage**

---

### **🌟 Contributors & Feedback**
If you have suggestions or want to contribute, open an issue or pull request on [GitHub](https://github.com/originvault/ov-id-sdk).

🚀 **Now, `ov-id-sdk` is ready to power decentralized identity in Web5!**
