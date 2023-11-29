import 'source-map-support/register'
import { APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult } from 'aws-lambda'
import { CreateTodoRequest } from '../../requests/CreateTodoRequest'
import {createTodo} from '../../businessLayer/todo'
import {createLogger} from "../../utils/logger";
import {getUserId} from "../utils";

const logger = createLogger('CreateTodos-API')

export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {

  const newTodo: CreateTodoRequest = JSON.parse(event.body)
  const userId = getUserId(event)

  logger.info('Create new Todo', {'newTodo': newTodo})

  const todo = await createTodo(newTodo, userId)
  return {
    statusCode: 202,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Credentials': true
    },
    body: JSON.stringify({
      todo
    })
  }
}
