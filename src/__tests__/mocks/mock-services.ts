import { IOVAgent } from '@originvault/ov-types';
import crypto from 'crypto';

/**
 * Mock services for testing without external dependencies
 */

export class MockCheqdProvider {
  private networkType: string;
  private rpcUrl: string;
  private cosmosPayerSeed: string;

  constructor(networkType: string, cosmosPayerSeed: string, rpcUrl: string) {
    this.networkType = networkType;
    this.cosmosPayerSeed = cosmosPayerSeed;
    this.rpcUrl = rpcUrl;
  }

  async createResource(params: any, options: any): Promise<string> {
    // Mock resource creation
    const resourceId = crypto.randomUUID();
    return `https://mock-resolver.example.com/identifiers/${params.options.payload.collectionId}/resources/${resourceId}`;
  }

  async resolveDid(did: string): Promise<any> {
    // Mock DID resolution
    return {
      didDocument: {
        id: did,
        verificationMethod: [{
          id: `${did}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyHex: crypto.randomBytes(32).toString('hex')
        }],
        authentication: [`${did}#key-1`]
      },
      didDocumentMetadata: {
        linkedResourceMetadata: []
      }
    };
  }
}

export class MockAgent implements Partial<IOVAgent> {
  private dids: Map<string, any> = new Map();
  private keys: Map<string, any> = new Map();
  private credentials: any[] = [];

  async didManagerCreate(options: any): Promise<any> {
    const did = options.options?.document?.id || `did:cheqd:testnet:${crypto.randomUUID()}`;
    const keyId = crypto.randomUUID();
    
    const didDocument = {
      did,
      provider: 'did:cheqd:testnet',
      keys: [{
        kid: keyId,
        type: 'Ed25519',
        kms: 'local',
        publicKeyHex: crypto.randomBytes(32).toString('hex')
      }],
      services: []
    };

    this.dids.set(did, didDocument);
    return didDocument;
  }

  async didManagerImport(options: any): Promise<any> {
    const didDocument = {
      did: options.did,
      provider: options.provider,
      keys: options.keys || [],
      services: []
    };

    this.dids.set(options.did, didDocument);
    return didDocument;
  }

  async didManagerGet(options: any): Promise<any> {
    return this.dids.get(options.did) || null;
  }

  async didManagerFind(options?: any): Promise<any[]> {
    if (options?.provider) {
      return Array.from(this.dids.values()).filter(did => did.provider === options.provider);
    }
    return Array.from(this.dids.values());
  }

  async keyManagerCreate(options: any): Promise<any> {
    const keyId = crypto.randomUUID();
    const key = {
      kid: keyId,
      type: options.type,
      kms: options.kms,
      publicKeyHex: crypto.randomBytes(32).toString('hex'),
      privateKeyHex: crypto.randomBytes(32).toString('hex')
    };

    this.keys.set(keyId, key);
    return key;
  }

  async keyManagerImport(options: any): Promise<any> {
    const key = {
      kid: options.kid || crypto.randomUUID(),
      type: options.type,
      kms: options.kms,
      publicKeyHex: crypto.randomBytes(32).toString('hex'),
      privateKeyHex: options.privateKeyHex
    };

    this.keys.set(key.kid, key);
    return key;
  }

  async keyManagerGet(options: any): Promise<any> {
    return this.keys.get(options.kid) || null;
  }

  async keyManagerSign(options: any): Promise<string> {
    // Mock signature generation
    return crypto.randomBytes(64).toString('base64');
  }

  async keyManagerVerify(options: any): Promise<boolean> {
    // Mock signature verification - always return true for testing
    return true;
  }

  async createVerifiableCredential(options: any): Promise<any> {
    const credential = {
      ...options.credential,
      proof: {
        type: 'JwtProof2020',
        jwt: `mock-jwt-${crypto.randomUUID()}`
      }
    };

    this.credentials.push(credential);
    return credential;
  }

  async verifyCredential(options: any): Promise<any> {
    // Mock credential verification
    return {
      verified: true,
      credential: options.credential
    };
  }

  async resolveDid(options: any): Promise<any> {
    const did = options.didUrl;
    return {
      didDocument: {
        id: did,
        verificationMethod: [{
          id: `${did}#key-1`,
          type: 'Ed25519VerificationKey2020',
          controller: did,
          publicKeyHex: crypto.randomBytes(32).toString('hex')
        }],
        authentication: [`${did}#key-1`]
      },
      didDocumentMetadata: {
        linkedResourceMetadata: []
      }
    };
  }

  async packDIDCommMessage(options: any): Promise<string> {
    // Mock DIDComm message packing
    return `mock-packed-message-${crypto.randomUUID()}`;
  }

  async unpackDIDCommMessage(options: any): Promise<any> {
    // Mock DIDComm message unpacking
    return {
      message: {
        id: crypto.randomUUID(),
        type: 'https://didcomm.org/basicmessage/2.0/message',
        to: 'did:test:recipient',
        from: 'did:test:sender',
        body: {
          content: 'Mock unpacked message'
        }
      }
    };
  }

  async sendDIDCommMessage(options: any): Promise<any> {
    // Mock message sending
    return {
      messageId: options.messageId,
      status: 'sent',
      timestamp: new Date().toISOString()
    };
  }
}

export class MockDatabase {
  private data: Map<string, any> = new Map();

  async save(key: string, value: any): Promise<void> {
    this.data.set(key, value);
  }

  async get(key: string): Promise<any> {
    return this.data.get(key) || null;
  }

  async delete(key: string): Promise<boolean> {
    return this.data.delete(key);
  }

  async list(): Promise<any[]> {
    return Array.from(this.data.values());
  }

  async clear(): Promise<void> {
    this.data.clear();
  }
}

export class MockFileSystem {
  private files: Map<string, string> = new Map();

  writeFileSync(path: string, data: string): void {
    this.files.set(path, data);
  }

  readFileSync(path: string): string {
    return this.files.get(path) || '';
  }

  existsSync(path: string): boolean {
    return this.files.has(path);
  }

  unlinkSync(path: string): void {
    this.files.delete(path);
  }

  mkdirSync(path: string, options?: any): void {
    // Mock directory creation
  }

  rmdirSync(path: string): void {
    // Mock directory removal
  }

  statSync(path: string): any {
    return {
      isFile: () => this.files.has(path),
      isDirectory: () => false
    };
  }
}

export class MockNetwork {
  private responses: Map<string, any> = new Map();

  setResponse(url: string, response: any): void {
    this.responses.set(url, response);
  }

  async get(url: string): Promise<any> {
    const response = this.responses.get(url);
    if (response) {
      return { data: response };
    }
    throw new Error(`No mock response for URL: ${url}`);
  }

  async post(url: string, data: any): Promise<any> {
    const response = this.responses.get(url);
    if (response) {
      return { data: response };
    }
    throw new Error(`No mock response for URL: ${url}`);
  }
}

export class MockCrypto {
  static randomBytes(size: number): Buffer {
    return crypto.randomBytes(size);
  }

  static createHash(algorithm: string): any {
    return crypto.createHash(algorithm);
  }

  static createCipheriv(algorithm: string, key: Buffer, iv: Buffer): any {
    return crypto.createCipheriv(algorithm, key, iv);
  }

  static createDecipheriv(algorithm: string, key: Buffer, iv: Buffer): any {
    return crypto.createDecipheriv(algorithm, key, iv);
  }

  static generateKeyPairSync(type: string, options: any): any {
    return crypto.generateKeyPairSync(type, options);
  }

  static publicEncrypt(options: any, data: Buffer): Buffer {
    return crypto.publicEncrypt(options, data);
  }

  static privateDecrypt(options: any, data: Buffer): Buffer {
    return crypto.privateDecrypt(options, data);
  }
}

export class MockEnvironment {
  private variables: Map<string, string> = new Map();

  set(key: string, value: string): void {
    this.variables.set(key, value);
  }

  get(key: string): string | undefined {
    return this.variables.get(key);
  }

  delete(key: string): void {
    this.variables.delete(key);
  }

  clear(): void {
    this.variables.clear();
  }
}

export class MockTimer {
  private timers: Map<string, any> = new Map();

  setTimeout(callback: Function, delay: number): string {
    const id = crypto.randomUUID();
    this.timers.set(id, { callback, delay, type: 'timeout' });
    return id;
  }

  setInterval(callback: Function, delay: number): string {
    const id = crypto.randomUUID();
    this.timers.set(id, { callback, delay, type: 'interval' });
    return id;
  }

  clearTimeout(id: string): void {
    this.timers.delete(id);
  }

  clearInterval(id: string): void {
    this.timers.delete(id);
  }

  tick(ms: number): void {
    // Mock time advancement
    for (const [id, timer] of this.timers) {
      if (timer.type === 'timeout' && timer.delay <= ms) {
        timer.callback();
        this.timers.delete(id);
      }
    }
  }
}

export class MockLogger {
  private logs: any[] = [];

  log(message: string, ...args: any[]): void {
    this.logs.push({ level: 'log', message, args, timestamp: new Date() });
  }

  error(message: string, ...args: any[]): void {
    this.logs.push({ level: 'error', message, args, timestamp: new Date() });
  }

  warn(message: string, ...args: any[]): void {
    this.logs.push({ level: 'warn', message, args, timestamp: new Date() });
  }

  info(message: string, ...args: any[]): void {
    this.logs.push({ level: 'info', message, args, timestamp: new Date() });
  }

  debug(message: string, ...args: any[]): void {
    this.logs.push({ level: 'debug', message, args, timestamp: new Date() });
  }

  getLogs(): any[] {
    return [...this.logs];
  }

  clearLogs(): void {
    this.logs = [];
  }

  getLogsByLevel(level: string): any[] {
    return this.logs.filter(log => log.level === level);
  }
}

export class MockPerformance {
  private marks: Map<string, number> = new Map();

  mark(name: string): void {
    this.marks.set(name, performance.now());
  }

  measure(name: string, startMark: string, endMark?: string): any {
    const start = this.marks.get(startMark) || 0;
    const end = endMark ? (this.marks.get(endMark) || performance.now()) : performance.now();
    return {
      name,
      duration: end - start,
      startTime: start,
      endTime: end
    };
  }

  now(): number {
    return performance.now();
  }
}

export class MockStorage {
  private storage: Map<string, string> = new Map();

  setItem(key: string, value: string): void {
    this.storage.set(key, value);
  }

  getItem(key: string): string | null {
    return this.storage.get(key) || null;
  }

  removeItem(key: string): void {
    this.storage.delete(key);
  }

  clear(): void {
    this.storage.clear();
  }

  key(index: number): string | null {
    const keys = Array.from(this.storage.keys());
    return keys[index] || null;
  }

  get length(): number {
    return this.storage.size;
  }
}

export class MockEventEmitter {
  private listeners: Map<string, Function[]> = new Map();

  on(event: string, listener: Function): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(listener);
  }

  off(event: string, listener: Function): void {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      const index = eventListeners.indexOf(listener);
      if (index > -1) {
        eventListeners.splice(index, 1);
      }
    }
  }

  emit(event: string, ...args: any[]): boolean {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      eventListeners.forEach(listener => listener(...args));
      return true;
    }
    return false;
  }

  removeAllListeners(event?: string): void {
    if (event) {
      this.listeners.delete(event);
    } else {
      this.listeners.clear();
    }
  }
}

export class MockValidator {
  private rules: Map<string, Function> = new Map();

  addRule(name: string, validator: Function): void {
    this.rules.set(name, validator);
  }

  validate(data: any, rules: string[]): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    for (const rule of rules) {
      const validator = this.rules.get(rule);
      if (validator && !validator(data)) {
        errors.push(`Validation failed for rule: ${rule}`);
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }
}

export class MockCache {
  private cache: Map<string, { value: any; expires: number }> = new Map();

  set(key: string, value: any, ttl?: number): void {
    const expires = ttl ? Date.now() + ttl : Infinity;
    this.cache.set(key, { value, expires });
  }

  get(key: string): any {
    const item = this.cache.get(key);
    if (item && item.expires > Date.now()) {
      return item.value;
    }
    if (item) {
      this.cache.delete(key);
    }
    return null;
  }

  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  clear(): void {
    this.cache.clear();
  }

  has(key: string): boolean {
    const item = this.cache.get(key);
    if (item && item.expires > Date.now()) {
      return true;
    }
    if (item) {
      this.cache.delete(key);
    }
    return false;
  }
}
