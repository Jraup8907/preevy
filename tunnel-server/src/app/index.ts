import fastify, { FastifyServerFactory, RawServerDefault } from 'fastify'
import { fastifyRequestContext } from '@fastify/request-context'
import http from 'http'
import { Logger } from 'pino'
import { KeyObject } from 'crypto'
import { validatorCompiler, serializerCompiler, ZodTypeProvider } from 'fastify-type-provider-zod'
import { SessionStore } from '../session'
import { Claims, cliIdentityProvider, jwtAuthenticator, saasIdentityProvider } from '../auth'
import { ActiveTunnelStore } from '../tunnel-store'
import { Proxy } from '../proxy'
import { login } from './login'
import { profileTunnels } from './tunnels'

const HEALTZ_URL = '/healthz'

const serverFactory = ({
  log,
  baseUrl,
  proxy,
}: {
  log: Logger
  baseUrl: URL
  proxy: Proxy
}): FastifyServerFactory<RawServerDefault> => handler => {
  const baseHostname = baseUrl.hostname
  const authHostname = `auth.${baseHostname}`
  const apiHostname = `api.${baseHostname}`

  log.debug('apiHostname %j', apiHostname)
  log.debug('authHostname %j', authHostname)

  const isNonProxyRequest = ({ headers }: http.IncomingMessage) => {
    const host = headers.host?.split(':')?.[0]
    return (host === authHostname) || (host === apiHostname)
  }

  const server = http.createServer((req, res) => {
    if (req.url !== HEALTZ_URL) {
      log.debug('request %j', { method: req.method, url: req.url, headers: req.headers })
    }
    const proxyHandler = !isNonProxyRequest(req) && proxy.routeRequest(req)
    return proxyHandler ? proxyHandler(req, res) : handler(req, res)
  })
    .on('upgrade', (req, socket, head) => {
      log.debug('upgrade %j', { method: req.method, url: req.url, headers: req.headers })
      const proxyHandler = !isNonProxyRequest(req) && proxy.routeUpgrade(req)
      if (proxyHandler) {
        return proxyHandler(req, socket, head)
      }

      log.warn('upgrade request %j not found', { method: req.method, url: req.url, host: req.headers.host })
      socket.end('Not found')
      return undefined
    })
  return server
}

export const createApp = async ({
  proxy,
  sessionStore,
  baseUrl,
  saasBaseUrl,
  activeTunnelStore,
  log,
  loginUrl,
  saasPublicKey,
  jwtSaasIssuer,
}: {
  log: Logger
  baseUrl: URL
  saasBaseUrl: URL
  loginUrl: URL
  sessionStore: SessionStore<Claims>
  activeTunnelStore: Pick<ActiveTunnelStore, 'get' | 'getByPkThumbprint'>
  proxy: Proxy
  saasPublicKey: KeyObject
  jwtSaasIssuer: string
}) => {
  const app = await fastify({ logger: log, serverFactory: serverFactory({ log, baseUrl, proxy }) })
  app.setValidatorCompiler(validatorCompiler)
  app.setSerializerCompiler(serializerCompiler)
  app.withTypeProvider<ZodTypeProvider>()
  await app.register(fastifyRequestContext)

  app.get(HEALTZ_URL, { logLevel: 'warn' }, async () => 'OK')

  await app.register(
    login,
    { log, baseUrl, sessionStore, activeTunnelStore, saasBaseUrl, loginUrl, saasPublicKey, jwtSaasIssuer },
  )

  await app.register(
    profileTunnels,
    { log, activeTunnelStore, saasPublicKey, jwtSaasIssuer },
  )

  return app
}
