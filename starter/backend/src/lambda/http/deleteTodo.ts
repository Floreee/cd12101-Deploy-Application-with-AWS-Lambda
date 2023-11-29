import 'source-map-support/register'

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda'
import * as middy from 'middy'
import { cors, httpErrorHandler } from 'middy/middlewares'

import { getUserId } from '../utils'
import { deleteTodo } from '../../handlers/todos'

export const handler = middy(
  async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const todoId = event.pathParameters.todoId
    const userId = getUserId(event)
    try {
      await deleteTodo(todoId, userId)
      return {
        headers: {
          'Access-Control-Allow-Origin': '*',
        },
        statusCode: 204,
        body: ''
      }
    } catch (error) {
      return {
        statusCode: 500,
        body: JSON.stringify({
          message: 'server error'
        })
      }
    }
  }
)

handler.use(httpErrorHandler()).use(
  cors({
    credentials: true
  })
)
