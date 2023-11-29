import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify} from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
//import Axios from 'axios'
// import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

const cert = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJNL7Wcwp4WTv4MA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi1wbG5iYjJuZXNtM2x1MWlsLnVzLmF1dGgwLmNvbTAeFw0yMzExMjcx
OTI4NDhaFw0zNzA4MDUxOTI4NDhaMCwxKjAoBgNVBAMTIWRldi1wbG5iYjJuZXNt
M2x1MWlsLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALu1jE0H7aXY8uIC/tHPAmDprJv28DRd72cNiUAHFYu++SQYtOc63d3dgXVc
J3uY6lkUdcsLswLU/S9ypMJaevlVolf3SL0zn7TYeBPElidQAdg8t66SPOzOtjyO
Q8hi7xLpb46cMEuzHJKLktix/zvP3v4zluA0g5UUdqZ8S1wK4jC2i7EaT/Zdw3u6
tFJIVnzfy2CkU6ryii6fFzD9QEfHxwY8OQa4l5CCLIg0e/WpvcJdmHv6F6POBBQU
JFqkF5rkwCHhRc9JQWhr6dg60S+QReGtHMq9GWRQJRmtXY8QQ+zC7R1FnRjy82Ss
bHitOZwf/K7TqKQdWU7D1P+as/8CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUCZEPO4pPsQkCbrn6KnM2S/FH+l0wDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQBIo0igiwxbYSA4gEvy5u9dVovQ2yoLA10VEF6rZ3lQ
cZMKywEBhqRYCeneOgUiBzA933yWwdNWuJBv4tqJHn2/dbh6ePQu4FRpMoZgD0Ry
kjXNgjQBP6HRJAR0bFVKynCciVNWkoi8iyye6BZkhpQI0YzCbdQOrdjGaaIT3bi6
miyaKneyOBZHzlw9jWvGWO+wYPjXWttvGHkpiM47HaI0JbVbT8ltX3v882mUpqts
Hjv9e7V0+IP6kqkZdzqNY2l0WiM7ld/q1rNVPk4k3mcoTD57VxVkuHn2AQFH/xcH
afbDJjE9lGTPZrnHdbiptMamizAvRhSdWBBtdcHuCta0
-----END CERTIFICATE-----`

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  // TODO: Implement token verification
  const jwtToken = getToken(authHeader)
  return verify(jwtToken, cert, { algorithms: ['RS256']}) as JwtPayload
}

export function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
