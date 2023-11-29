import 'source-map-support/register'
import {APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult} from 'aws-lambda'
import {UpdateTodoRequest} from '../../requests/UpdateTodoRequest'
import {updateTodo} from '../../businessLayer/todo'
import {getUserId} from "../utils";
import {createLogger} from "../../utils/logger";

const logger = createLogger('UpdateTodos-API')

export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    const todoId = event.pathParameters.todoId
    const updatedTodo: UpdateTodoRequest = JSON.parse(event.body)
    const userId = getUserId(event)

    logger.info('Update todo', {'todoId': todoId, 'updatedTodo': updatedTodo})
    const todo = await updateTodo(updatedTodo, userId, todoId)

    return {
        statusCode: 200,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': true
        },
        body: JSON.stringify({
            todo
        })
    }
}

