const apiId = 'ysldqeb36a'
//endpoint for online
export const apiEndpoint = `https://${apiId}.execute-api.us-east-1.amazonaws.com/dev`

//endpoint for offline
//export const apiEndpoint = `http://localhost:3003/dev`

export const authConfig = {
  domain: 'dev-plnbb2nesm3lu1il.us.auth0.com',            // Auth0 domain
  clientId: 'wJzMUd6zlDjWqQozDHcotc93lS6KxmK7',          // Auth0 client id
  callbackUrl: 'http://localhost:3000/callback'
}
