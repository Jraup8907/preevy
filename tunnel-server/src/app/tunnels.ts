import { FastifyPluginAsync } from 'fastify'
import { Logger } from 'pino'
import z from 'zod'
import { KeyObject } from 'crypto'
import { ActiveTunnelStore } from '../tunnel-store'
import { cliIdentityProvider, saasIdentityProvider, jwtAuthenticator } from '../auth'
import { UnauthorizedError } from '../http-server-helpers'

const paramsSchema = z.object({
  profileId: z.string(),
})

export const profileTunnels: FastifyPluginAsync<{
  log: Logger
  activeTunnelStore: Pick<ActiveTunnelStore, 'getByPkThumbprint'>
  saasPublicKey: KeyObject
  jwtSaasIssuer: string
}> = async (app, { activeTunnelStore, saasPublicKey, jwtSaasIssuer }) => {
  const saasIdp = saasIdentityProvider(jwtSaasIssuer, saasPublicKey)
  app.get<{
    Params: z.infer<typeof paramsSchema>
  }>('/profiles/:profileId/tunnels', async (req, res) => {
    const { params: { profileId } } = req
    const tunnels = (await activeTunnelStore.getByPkThumbprint(profileId))
    if (!tunnels?.length) return []

    const auth = jwtAuthenticator(
      profileId,
      [saasIdp, cliIdentityProvider(tunnels[0].publicKey, tunnels[0].publicKeyThumbprint)]
    )

    const result = await auth(req.raw)

    if (!result.isAuthenticated) {
      throw new UnauthorizedError()
    }

    return await res.send(tunnels.map(t => ({
      envId: t.envId,
      hostname: t.hostname,
      access: t.access,
      meta: t.meta,
    })))
  })
}
