import { join } from 'node:path'
import { editUrl } from '../url'

export const calcLoginUrl = ({ loginUrl }: { loginUrl: URL }) => (
  { env, returnPath }: { env: string; returnPath?: string },
) => editUrl(loginUrl, {
  queryParams: {
    env,
    ...(returnPath && { returnPath }),
  },
}).toString()

export const calcSaasLoginUrl = ({ loginUrl, saasBaseUrl }: {
  loginUrl: URL
  saasBaseUrl: URL
}) => {
  const calcLogin = calcLoginUrl({ loginUrl })
  return ({ env, returnPath }: { env: string; returnPath?: string}) => editUrl(saasBaseUrl, {
    queryParams: { redirectTo: calcLogin({ env, returnPath }) },
    path: join(saasBaseUrl.pathname, '/api/auth/login'),
  }).toString()
}
