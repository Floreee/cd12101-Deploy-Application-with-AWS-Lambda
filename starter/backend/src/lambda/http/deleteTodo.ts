import 'source-map-support/register'
import {createLogger} from "../../utils/logger";
import { APIGatewayProxyEvent, APIGatewayProxyResult, APIGatewayProxyHandler } from 'aws-lambda'
import {getUserId} from "../utils";
import {deleteTodo} from "../../businessLayer/todo";
const logger = createLogger('DeleteTodos-API')

export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {

  const todoId = event.pathParameters.todoId
  const userId = getUserId(event)

  logger.info('Delete Todo-ID', todoId)
  // TODO: Remove a TODO item by id
  await deleteTodo(userId, todoId)
  return   {
    statusCode: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true
    },
    body: JSON.stringify({
      todoId
    })
  }
}
