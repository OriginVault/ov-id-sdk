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
    '^(\\.{1,2}/.*)\\.js$': '$1'
  },
  modulePathIgnorePatterns: ["<rootDir>/dist/"],
  transformIgnorePatterns: [
    'node_modules/(?!(@veramo|@cheqd|@ipld|multiformats|uint8arrays)/)'
  ]
};
