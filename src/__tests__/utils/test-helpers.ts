import { IOVAgent } from '@originvault/ov-types';
import { createOVAgent, createCheqdProvider, CheqdNetwork } from '../../OVAgent.js';
import { getUniversalResolverFor } from '@veramo/did-resolver';
import { ed25519 } from '@noble/curves/ed25519';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import rpj from 'read-package-json-fast';
import path from 'path';

/**
 * Test environment setup and utilities
 */

export interface TestEnvironment {
  agent: IOVAgent;
  testDID: string;
  testPrivateKey: string;
  testPublicKey: string;
  cleanup: () => Promise<void>;
}

export interface MockCredentials {
  testUser: {
    did: string;
    privateKey: string;
    publicKey: string;
  };
  testIssuer: {
    did: string;
    privateKey: string;
    publicKey: string;
  };
}

/**
 * Creates a test environment with a mock agent and test credentials
 */
export async function createTestEnvironment(): Promise<TestEnvironment> {
  // Prefer testnet variables from environment
  const payerSeed = process.env.COSMOS_PAYER_SEED || process.env.TESTNET_MNEMONIC || 'test-seed-phrase-for-testing-only';
  const rpcUrl = process.env.CHEQD_TESTNET_RPC_URL || process.env.CHEQD_RPC_URL || 'https://rpc.cheqd.network';

  // Create a Cheqd testnet provider for testing
  const mockCheqdProvider = createCheqdProvider(
    CheqdNetwork.Testnet,
    payerSeed,
    rpcUrl
  );

  const universalResolver = getUniversalResolverFor(['cheqd', 'key']);
  
  // Create test agent
  const agent = createOVAgent({
    cheqdProvider: mockCheqdProvider,
    universalResolver,
    additionalResolvers: {}
  });

  // Resolve test DID from package.json if provided, otherwise generate ephemeral did:key
  let testDIDFromPackage: string | undefined;
  try {
    const pkgPath = path.join(process.cwd(), 'package.json');
    const pkg = await rpj(pkgPath);
    // support both testDid and testDID just in case
    // @ts-ignore - dynamic json shape
    testDIDFromPackage = (pkg as any).testDid || (pkg as any).testDID;
  } catch {}

  // Generate test keys
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);

  const generatedDidKey = `did:key:${Buffer.from(publicKey).toString('base64')}`;
  const testDID = testDIDFromPackage || generatedDidKey;
  const testPrivateKey = Buffer.from(privateKey).toString('hex');
  const testPublicKey = Buffer.from(publicKey).toString('hex');

  const cleanup = async () => {
    // Cleanup test data
    try {
      // Remove any test DIDs from agent
      const dids = await agent.didManagerFind();
      for (const did of dids) {
        if (did.did.includes('test') || did.alias?.includes('test')) {
          await agent.didManagerDelete({ did: did.did });
        }
      }
    } catch (error) {
      // Ignore cleanup errors
    }
  };

  return {
    agent,
    testDID,
    testPrivateKey,
    testPublicKey,
    cleanup
  };
}

/**
 * Creates mock credentials for testing
 */
export function createMockCredentials(): MockCredentials {
  const userPrivateKey = ed25519.utils.randomPrivateKey();
  const userPublicKey = ed25519.getPublicKey(userPrivateKey);
  
  const issuerPrivateKey = ed25519.utils.randomPrivateKey();
  const issuerPublicKey = ed25519.getPublicKey(issuerPrivateKey);

  return {
    testUser: {
      did: `did:key:${Buffer.from(userPublicKey).toString('base64')}`,
      privateKey: Buffer.from(userPrivateKey).toString('hex'),
      publicKey: Buffer.from(userPublicKey).toString('hex')
    },
    testIssuer: {
      did: `did:key:${Buffer.from(issuerPublicKey).toString('base64')}`,
      privateKey: Buffer.from(issuerPrivateKey).toString('hex'),
      publicKey: Buffer.from(issuerPublicKey).toString('hex')
    }
  };
}

/**
 * Utility function to wait for a specified amount of time
 */
export function wait(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Generates a random test string
 */
export function generateTestString(length: number = 10): string {
  return Math.random().toString(36).substring(2, 2 + length);
}

/**
 * Creates a test message for DIDComm testing
 */
export function createTestMessage(): any {
  return {
    id: uuidv4(),
    type: 'https://didcomm.org/basicmessage/2.0/message',
    body: {
      content: `Test message ${generateTestString()}`,
      timestamp: new Date().toISOString()
    }
  };
}

/**
 * Sets up test environment variables
 */
export function setupTestEnv(): void {
  process.env.NODE_ENV = 'test';
  if (!process.env.COSMOS_PAYER_SEED) {
    process.env.COSMOS_PAYER_SEED = process.env.TESTNET_MNEMONIC || 'test-seed-for-testing-only';
  }
  if (!process.env.CHEQD_TESTNET_RPC_URL) {
    process.env.CHEQD_TESTNET_RPC_URL = 'https://rpc.cheqd.network';
  }
}

/**
 * Cleans up test environment
 */
export function cleanupTestEnv(): void {
  delete process.env.NODE_ENV;
  delete process.env.COSMOS_PAYER_SEED;
  delete process.env.CHEQD_RPC_URL;
  delete process.env.CHEQD_TESTNET_RPC_URL;
}

/**
 * Utility to test async functions that should throw
 */
export async function expectToThrow(
  fn: () => Promise<any>,
  expectedMessage?: string
): Promise<void> {
  try {
    await fn();
    throw new Error('Expected function to throw, but it did not');
  } catch (error) {
    if (expectedMessage && (!(error instanceof Error) || !error.message.includes(expectedMessage))) {
      throw new Error(`Expected error message to contain "${expectedMessage}", but got: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

/**
 * Creates test biometric data
 */
export function createTestBiometricData(): any {
  return {
    fingerprint: generateTestString(32),
    faceTemplate: generateTestString(64),
    voiceprint: generateTestString(48),
    deviceFingerprint: generateTestString(40)
  };
}

/**
 * Performance testing utilities
 */
export class PerformanceTimer {
  private startTime: number = 0;
  private endTime: number = 0;

  start(): void {
    this.startTime = performance.now();
  }

  stop(): number {
    this.endTime = performance.now();
    return this.getDuration();
  }

  getDuration(): number {
    return this.endTime - this.startTime;
  }
}

/**
 * Memory usage utilities
 */
export function getMemoryUsage(): NodeJS.MemoryUsage {
  return process.memoryUsage();
}

/**
 * Creates a test verifiable credential
 */
export function createTestCredential(issuer: string, subject: string): any {
  return {
    id: uuidv4(),
    issuer: { id: issuer },
    credentialSubject: {
      id: subject,
      assertionType: 'test-credential',
      assertionDate: new Date().toISOString(),
      assertionResult: 'Passed'
    },
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential'],
    expirationDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
  };
}

/**
 * Mock data generators
 */
export const MockData = {
  generatePrivateKey: (): string => {
    return Buffer.from(ed25519.utils.randomPrivateKey()).toString('hex');
  },

  generatePublicKey: (privateKey?: string): string => {
    const privKey = privateKey ? Buffer.from(privateKey, 'hex') : ed25519.utils.randomPrivateKey();
    return Buffer.from(ed25519.getPublicKey(privKey)).toString('hex');
  },

  generateDID: (): string => {
    const privateKey = ed25519.utils.randomPrivateKey();
    const publicKey = ed25519.getPublicKey(privateKey);
    return `did:key:${Buffer.from(publicKey).toString('base64')}`;
  },

  generateMessage: (): string => {
    return `Test message ${crypto.randomBytes(16).toString('hex')}`;
  },

  generatePassword: (): string => {
    return crypto.randomBytes(32).toString('base64');
  }
};

/**
 * Test assertions helpers
 */
export const TestAssertions = {
  isValidHex: (str: string): boolean => {
    return /^[0-9a-fA-F]*$/.test(str);
  },

  isValidBase64: (str: string): boolean => {
    try {
      return btoa(atob(str)) === str;
    } catch {
      return false;
    }
  },

  isValidDID: (did: string): boolean => {
    return did.startsWith('did:') && did.split(':').length >= 3;
  },

  isValidTimestamp: (timestamp: string): boolean => {
    return !isNaN(Date.parse(timestamp));
  }
};