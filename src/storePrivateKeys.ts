import keytar from "keytar";
import axios from "axios";

const SERVICE_NAME = "veramo-key-store";
const PRIMARY_DID_KEY = "primary-did";

// ✅ Fetch DID Configuration from a Domain
async function fetchDomainDID(domain: string): Promise<string | null> {
  try {
    const url = `https://${domain}/.well-known/did-configuration.json`;
    const response = await axios.get(url);
    const data = response.data;

    if (data?.linked_dids?.length) {
      return data.linked_dids[0].id; // Use the first listed DID
    }
  } catch (error) {
    console.error(`❌ Failed to fetch DID configuration from ${domain}:`, error);
  }

  return null;
}

// ✅ Set the primary DID (User Defined or Domain Verified)
export async function setPrimaryDID(did: string): Promise<void> {
  await keytar.setPassword(SERVICE_NAME, PRIMARY_DID_KEY, did);
}

// ✅ Retrieve the primary DID (First checking SecureKeyStore, then Domain)
export async function getPrimaryDID(): Promise<string | null> {
  // First, check if a user-defined primary DID is set
  const storedDID = await keytar.getPassword(SERVICE_NAME, PRIMARY_DID_KEY);
  if (storedDID) return storedDID;

  // If no user-defined primary DID, try fetching from domain
  const domain = process.env.SDK_DOMAIN; // Ensure this is set in the environment
  if (!domain) {
    console.error("❌ No domain set for SDK validation.");
    return null;
  }

  return await fetchDomainDID(domain);
}

export async function storePrivateKey(did: string, privateKey: string): Promise<void> {
  await keytar.setPassword(SERVICE_NAME, did, privateKey);
}

export async function retrievePrivateKey(did: string): Promise<string | null> {
  return await keytar.getPassword(SERVICE_NAME, did);
}

export async function listAllKeys(): Promise<Array<{ did: string, privateKey: string }>> {
  const credentials = await keytar.findCredentials(SERVICE_NAME);
  return credentials.map(cred => ({
    did: cred.account,
    privateKey: cred.password
  }));
}

export async function deleteKey(did: string): Promise<boolean> {
  return await keytar.deletePassword(SERVICE_NAME, did);
}

