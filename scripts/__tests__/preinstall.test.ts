import { ensureServiceCredential } from '../preinstall'
import { promises as fs } from 'fs'
import path from 'path'

describe('ensureServiceCredential', () => {
  const vcPath = path.resolve(process.cwd(), 'service-credential.json')

  beforeEach(() => {
    jest.resetAllMocks()
  })

  it('throws if service-credential.json is missing', async () => {
    jest.spyOn(fs, 'access').mockImplementation(() => {
      return Promise.reject(new Error('not found'))
    })

    await expect(ensureServiceCredential()).rejects.toThrow(
      '❌ Missing required ServiceCredential at project root: service-credential.json'
    )
  })

  it('throws if JSON is invalid', async () => {
    jest.spyOn(fs, 'access').mockResolvedValue(undefined)
    jest.spyOn(fs, 'readFile').mockResolvedValue('invalid json')

    await expect(ensureServiceCredential()).rejects.toThrow(
      '❌ service-credential.json is not valid JSON'
    )
  })

  it('throws if credential verification fails', async () => {
    const dummyVc = {
      type: ['ServiceCredential'],
      issuer: 'did:cheqd:cheqDeepCorp'
    }
    jest.spyOn(fs, 'access').mockResolvedValue(undefined)
    jest.spyOn(fs, 'readFile').mockResolvedValue(JSON.stringify(dummyVc))
    const { userAgent } = require('../../src/userAgent')
    userAgent.verifyVerifiableCredential.mockResolvedValue(false)

    await expect(ensureServiceCredential()).rejects.toThrow(
      '❌ Invalid or expired ServiceCredential'
    )
  })

  it('resolves if credential is valid', async () => {
    const dummyVc = {
      type: ['ServiceCredential'],
      issuer: 'did:cheqd:cheqDeepCorp'
    }
    jest.spyOn(fs, 'access').mockResolvedValue(undefined)
    jest.spyOn(fs, 'readFile').mockResolvedValue(JSON.stringify(dummyVc))
    const { userAgent } = require('../../src/userAgent')
    userAgent.verifyVerifiableCredential.mockResolvedValue(true)

    await expect(ensureServiceCredential()).resolves.toBeUndefined()
  })
}) 