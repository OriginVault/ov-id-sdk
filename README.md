# 🚀 `@originvault/ov-id-sdk`
**Decentralized Identity SDK for OriginVault**

`@originvault/ov-id-sdk` is a **TypeScript SDK** for managing **decentralized identities (DIDs)** and **verifiable credentials (VCs)** within the **OriginVault ecosystem**. It enables developers to create, import, and manage **DIDs**, securely store private keys, and sign/verify credentials using **Web5-native identity standards**.

## 🔹 Features
✅ **DID Creation & Import** → Generate or restore `did:cheqd` and `did:vda` identities  
✅ **Secure Key Storage** → Uses **OS keychain encryption (`keytar`)** instead of environment variables  
✅ **Primary DID Management** → Automatically selects a **default DID for signing**  
✅ **Verifiable Credential Signing & Verification** → Issue & verify **W3C-compliant credentials**  
✅ **Domain-Linked DID Discovery** → Auto-fetches the authoritative DID from `.well-known/did-configuration.json`  
✅ **Built with OV** → Designed to integrate seamlessly into **OriginVault’s Web5 trust layer**  

---

## 📦 Installation
```bash
npm install @originvault/ov-id-sdk
```

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

### **5️⃣ Automatically Fetch Domain-Linked DID**
```typescript
import { getPrimaryDID } from "@originvault/ov-id-sdk";

// ✅ If no primary DID is set, check `.well-known/did-configuration.json` on the SDK's domain
process.env.SDK_DOMAIN = "example.com"; // Set the domain for validation
const domainDID = await getPrimaryDID();
console.log("Domain-Verified DID:", domainDID);
```

---

## 🛠 Configuration
| **Environment Variable** | **Description** |
|------------------|-----------------------------------------------|
| `DID_DOMAIN` | (Optional) Domain to fetch `.well-known/did-configuration.json` |
| `DID_METHOD` | (Optional) Default DID method (`cheqd` or `vda`) |

---

## 🏗 Built With
- **[Cheqd DID SDK](https://docs.cheqd.io/)** → DID creation & verification  
- **[Verida DID](https://verida.io/)** → Identity-backed data storage  
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
