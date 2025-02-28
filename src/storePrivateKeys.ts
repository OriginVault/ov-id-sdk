import { Keyring } from '@polkadot/keyring';
import { cryptoWaitReady } from '@polkadot/util-crypto';
import axios from "axios";
import os from 'os';
import path from 'path';
import { agent } from './veramoAgent.js';
import * as ed25519 from '@noble/ed25519';
import multibase from 'multibase';
import dotenv from 'dotenv';

dotenv.config();

// Initialize keyring
let keyring: Keyring | undefined;

async function ensureKeyring(): Promise<Keyring> {
  if (!keyring) {
    await cryptoWaitReady();
    keyring = new Keyring({ type: 'ed25519' });
  }
  return keyring;
}

const KEYRING_FILE = path.join(os.homedir(), '.cheqd-did-keyring.json');

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
export async function setPrimaryDID(did: string, privateKey: string): Promise<boolean> {
  if (!privateKey) {
    console.error("❌ Private key must be provided to set primary DID");
    return false;
  }

  console.log("🔑 Setting primary DID", did);

  const resolvedDid = await agent.resolveDid({ didUrl: did });
  if (!resolvedDid) {
    console.error("❌ DID could not be resolved", did);
    return false;
  }
  const didDoc = resolvedDid.didDocument;

  const authentication = didDoc?.authentication?.[0];
  if (!authentication) {
    console.error("❌ No authentication found for DID", did);
    return false;
  }

  const verificationMethods = didDoc.verificationMethod;
  if (!verificationMethods) {
    console.error("❌ No verification method found for DID", did);
    return false;
  }

  const verifiedAuthentication = verificationMethods.find(method => method.id === authentication);
  if (!verifiedAuthentication) {
    console.error("❌ Could not find verification method for standard did authentication", did);
    return false;
  }

  const publicKeyMultibase = verifiedAuthentication.publicKeyMultibase;
  if (!publicKeyMultibase) {
    console.error("❌ No public key multibase found for verification method", did);
    return false;
  }

  try {
    const kr = await ensureKeyring();
    
    // Convert the private key from base64 to Uint8Array
    const privateKeyBytes = Uint8Array.from(Buffer.from(privateKey, 'base64'));
   
    // Derive public key
    const privateKeySub = privateKeyBytes.subarray(0, 32);

    const publicKeyBytes = await ed25519.getPublicKey(privateKeySub);
    const derivedPublicKey = Buffer.from(publicKeyBytes).toString('base64')
    
    // Convert base64 to buffer to base58
    const publicKeyBuffer = multibase.decode(Buffer.from(publicKeyMultibase, 'utf-8'));

    // Remove the first byte (Multibase prefix)
    const publicKeySliced = publicKeyBuffer.slice(2);

    // Convert to Base64 for comparison
    const documentPublicKey = Buffer.from(publicKeySliced).toString('base64');    
   
    // Compare without the multibase prefix
    if (derivedPublicKey !== documentPublicKey) {
      console.error("❌ Private key does not match the public key in DID document");
      return false;
    }

    console.log("✅ Private key verified against resolved DID");
    
    // Add the key pair to the keyring using the raw private key
    const pair = kr.addFromSeed(privateKeySub, { did, isPrimary: true });
    kr.addPair(pair);
    
    return true;
  } catch (error) {
    console.error("❌ Error setting primary DID:", error);
    return false;
  }
}

// ✅ Retrieve the primary DID
export async function getPrimaryDID(): Promise<string | null> {
  try {
    const kr = await ensureKeyring();
    const pairs = kr.getPairs();
    const primaryPair = pairs.find(p => p.meta?.isPrimary);
    const did = primaryPair?.meta?.did as string | undefined;
    if (did) return did;

    const domain = process.env.SDK_DOMAIN;
    console.log("🔑 Domain", domain);
    if (!domain) {
      console.error("❌ No domain set for SDK validation.");
      return null;
    }

    return await fetchDomainDID(domain);
  } catch (error) {
    console.error("❌ Error accessing keyring:", error);
    return null;
  }
}

export async function storePrivateKey(did: string, privateKey: string): Promise<void> {
  try {
    const kr = await ensureKeyring();
    const pair = kr.addFromUri(privateKey, { did, isPrimary: false });
    kr.addPair(pair);
  } catch (error) {
    console.error("❌ Error storing private key:", error);
    throw error;
  }
}

export async function retrievePrivateKey(did: string): Promise<string | null> {
  try {
    const kr = await ensureKeyring();
    const pairs = kr.getPairs();
    const pair = pairs.find(p => p.meta.did === did);
    return pair ? pair.address : null;
  } catch (error) {
    console.error("❌ Error retrieving private key:", error);
    return null;
  }
}

export async function listAllKeys(): Promise<Array<{ did: string, privateKey: string, isPrimary?: boolean }>> {
  try {
    const kr = await ensureKeyring();
    const pairs = kr.getPairs();
    return pairs.map(pair => ({
      did: pair.meta.did as string,
      privateKey: pair.address,
      isPrimary: pair.meta.isPrimary as boolean
    }));
  } catch (error) {
    console.error("❌ Error listing keys:", error);
    return [];
  }
}

export async function deleteKey(did: string): Promise<boolean> {
  try {
    const kr = await ensureKeyring();
    const pairs = kr.getPairs();
    const pair = pairs.find(p => p.meta.did === did);
    if (pair) {
      kr.removePair(pair.address);
      return true;
    }
    return false;
  } catch (error) {
    console.error("❌ Error deleting key:", error);
    return false;
  }
}

