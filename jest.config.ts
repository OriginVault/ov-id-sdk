// jest.config.mjs
import { defaultsESM } from 'ts-jest/presets';

export default {
  ...defaultsESM,
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts', '.tsx'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: true
    }],
    '^.+\\.js$': 'babel-jest'
  },
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '^@ipld/dag-pb$': '<rootDir>/src/__tests__/mocks/dag-pb.ts',
    '^multiformats/hashes/digest$': '<rootDir>/node_modules/multiformats/dist/src/hashes/digest.js',
    '^multiformats/cid$': '<rootDir>/node_modules/multiformats/dist/src/cid.js',
    '^multiformats/basics$': '<rootDir>/node_modules/multiformats/dist/src/basics.js',
    '^multiformats/bytes$': '<rootDir>/node_modules/multiformats/dist/src/bytes.js',
    '^multiformats/varint$': '<rootDir>/node_modules/multiformats/dist/src/varint.js',
    '^multiformats/bases/base58$': '<rootDir>/node_modules/multiformats/dist/src/bases/base58.js',
    '^multiformats/bases/base64$': '<rootDir>/node_modules/multiformats/dist/src/bases/base64.js',
    '^multiformats/bases/base32$': '<rootDir>/node_modules/multiformats/dist/src/bases/base32.js',
    '^base58-universal$': '<rootDir>/node_modules/base58-universal/dist/src/index.js',
    '^ipfs-unixfs$': '<rootDir>/node_modules/ipfs-unixfs/dist/src/index.js',
    '^protons-runtime$': '<rootDir>/node_modules/protons-runtime/dist/src/index.js',
    '^uint8-varint$': '<rootDir>/node_modules/uint8-varint/dist/src/index.js',
    '^uint8arrays$': '<rootDir>/node_modules/uint8arrays/dist/src/index.js'
  },
  resolver: undefined,
  modulePathIgnorePatterns: ["<rootDir>/dist/"],
  transformIgnorePatterns: [
    'node_modules/(?!(@veramo|@cheqd|@ipld|multiformats|uint8arrays|@noble|@multiformats|ipfs-unixfs|ipfs-http-client|ipfs-unixfs-importer|ipfs-unixfs-exporter|protons-runtime|uint8-varint|uint8arrays|@aviarytech|@digitalbazaar|base64url-universal|@lit-protocol|@digitalbazaar)/)'
  ],
  globals: {
    'ts-jest': {
      isolatedModules: true
    }
  },
  testMatch: [
    '<rootDir>/src/__tests__/**/*.test.ts',
    '<rootDir>/src/__tests__/**/*.test.js'
  ],
  collectCoverageFrom: [
    'src/**/*.{ts,js}',
    '!src/**/*.d.ts',
    '!src/__tests__/**',
    '!src/**/*.test.{ts,js}',
    '!src/**/*.spec.{ts,js}'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: [
    'text',
    'lcov',
    'html',
    'json'
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    }
  },
  setupFilesAfterEnv: ['<rootDir>/src/__tests__/setup/jest.setup.ts'],
  testTimeout: 30000,
  maxWorkers: '50%',
  verbose: true,
  detectOpenHandles: true,
  forceExit: true
};
