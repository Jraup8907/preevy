import { describe, beforeEach, it, expect, afterEach, jest, beforeAll } from '@jest/globals'
import crypto from 'node:crypto'
import pino from 'pino'
import pinoPretty from 'pino-pretty'
import { promisify } from 'node:util'
import fetch, { Response } from 'node-fetch'
import { Cookie } from 'tough-cookie'
import { calculateJwkThumbprintUri, exportJWK } from 'jose'
import { createApp } from './index'
import { SessionStore, cookieSessionStore } from '../session'
import { Claims, claimsSchema } from '../auth'
import { ActiveTunnel, ActiveTunnelStore } from '../tunnel-store'
import { EntryWatcher } from '../memory-store'

const mockFunction = <T extends (...args: never[]) => unknown>(): jest.MockedFunction<T> => (
  jest.fn() as unknown as jest.MockedFunction<T>
)

type MockInterface<T extends {}> = {
  [K in keyof T]: T[K] extends (...args: never[]) => unknown
    ? jest.MockedFunction<T[K]>
    : T[K]
}

const generateKeyPair = promisify(crypto.generateKeyPair)

const genKey = async () => {
  const kp = await generateKeyPair('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })

  const publicKey = crypto.createPublicKey(kp.publicKey)
  const publicKeyThumbprint = await calculateJwkThumbprintUri(await exportJWK(publicKey))

  return { publicKey, publicKeyThumbprint }
}

type Key = Awaited<ReturnType<typeof genKey>>

describe('app', () => {
  let saasKey: Key
  let envKey: Key

  beforeAll(async () => {
    saasKey = await genKey()
    envKey = await genKey()
  })

  let app: Awaited<ReturnType<typeof createApp>>
  let baseUrl: string
  type SessionStoreStore = ReturnType<SessionStore<Claims>>
  let sessionStoreStore: MockInterface<SessionStoreStore>
  let sessionStore: jest.MockedFunction<SessionStore<Claims>>
  let activeTunnelStore: MockInterface<Pick<ActiveTunnelStore, 'get' | 'getByPkThumbprint'>>
  let user: Claims | undefined

  const log = pino({
    level: 'debug',
  }, pinoPretty({ destination: pino.destination(process.stderr) }))

  beforeEach(async () => {
    user = undefined
    // sessionStoreStore = {
    //   save: mockFunction<SessionStoreStore['save']>(),
    //   set: mockFunction<SessionStoreStore['set']>(),
    //   get user() { return user },
    // }
    // sessionStore = mockFunction<SessionStore<Claims>>().mockReturnValue(sessionStoreStore)
    activeTunnelStore = {
      get: mockFunction<ActiveTunnelStore['get']>(),
      getByPkThumbprint: mockFunction<ActiveTunnelStore['getByPkThumbprint']>(),
    }

    app = await createApp({
      sessionStore: cookieSessionStore({ domain: 'base.livecycle.example', schema: claimsSchema }),
      activeTunnelStore,
      baseUrl: new URL('http://base.livecycle.example'),
      log,
      loginUrl: new URL('http://api.base.livecycle.example/login'),
      saasBaseUrl: new URL('http://saas.livecycle.example'),
      saasPublicKey: saasKey.publicKey,
      jwtSaasIssuer: 'saas.livecycle.example',
      proxy: {
        routeRequest: () => async () => undefined,
        routeUpgrade: () => async () => undefined,
      },
    })

    baseUrl = await app.listen({ host: '127.0.0.1', port: 0 })
  })

  afterEach(async () => {
    await app.close()
  })

  describe('login', () => {
    describe('when not given the required query params', () => {
      let response: Response
      beforeEach(async () => {
        response = await fetch(`${baseUrl}/login`, { redirect: 'manual', headers: { host: 'api.base.livecycle.example' } })
      })

      it('should return status code 400', () => {
        expect(response.status).toBe(400)
      })
    })

    describe('when given an env and a returnPath that does not start with /', () => {
      let response: Response
      beforeEach(async () => {
        response = await fetch(`${baseUrl}/login?env=myenv&returnPath=bla`, { redirect: 'manual', headers: { host: 'api.base.livecycle.example' } })
      })

      it('should return status code 400', () => {
        expect(response.status).toBe(400)
      })
    })

    describe('when given a nonexistent env and a valid returnPath', () => {
      let response: Response
      beforeEach(async () => {
        response = await fetch(`${baseUrl}/login?env=myenv&returnPath=/bla`, { redirect: 'manual', headers: { host: 'api.base.livecycle.example' } })
      })

      it('should return status code 404', async () => {
        expect(response.status).toBe(404)
      })

      it('should return a descriptive message in the body JSON', async () => {
        expect(await response.json()).toHaveProperty('message', 'Unknown envId: myenv')
      })
    })

    describe('when given an existing env and a valid returnPath and no session or authorization header', () => {
      let response: Response
      beforeEach(async () => {
        activeTunnelStore.get.mockImplementation(async () => ({
          value: {
            publicKeyThumbprint: envKey.publicKeyThumbprint,
          } as ActiveTunnel,
          watcher: undefined as unknown as EntryWatcher,
        }))
        response = await fetch(`${baseUrl}/login?env=myenv&returnPath=/bla`, { redirect: 'manual', headers: { host: 'api.base.livecycle.example' } })
      })

      it('should return a redirect to the saas login page', async () => {
        expect(response.status).toBe(302)
        const locationHeader = response.headers.get('location')
        expect(locationHeader).toMatch('http://saas.livecycle.example/api/auth/login')
        const redirectUrl = new URL(locationHeader as string)
        const redirectBackUrlStr = redirectUrl.searchParams.get('redirectTo')
        expect(redirectBackUrlStr).toBeDefined()
        expect(redirectBackUrlStr).toMatch('http://api.base.livecycle.example/login')
        const redirectBackUrl = new URL(redirectBackUrlStr as string)
        expect(redirectBackUrl.searchParams.get('env')).toBe('myenv')
        expect(redirectBackUrl.searchParams.get('returnPath')).toBe('/bla')
      })
    })

    describe('when given an existing env and a valid returnPath and a session cookie', () => {
      let response: Response
      beforeEach(async () => {
        activeTunnelStore.get.mockImplementation(async () => ({
          value: {
            publicKeyThumbprint: envKey.publicKeyThumbprint,
          } as ActiveTunnel,
          watcher: undefined as unknown as EntryWatcher,
        }))
        response = await fetch(`${baseUrl}/login?env=myenv&returnPath=/bla`, {
          redirect: 'manual',
          headers: {
            host: 'api.base.livecycle.example',
            cookie: new Cookie({
              domain: 'base.livecycle.example',
              key: `preevy-${envKey.publicKeyThumbprint}`,
              value: JSON.stringify({}),
              secure: true,
              httpOnly: true,
            }).cookieString(),
          },
        })
      })

      it.only('should return a redirect to the env page', async () => {
        expect(response.status).toBe(302)
        const locationHeader = response.headers.get('location')
        expect(locationHeader).toBe('http://myenv.base.livecycle.example/bla')
      })
    })
  })
})
