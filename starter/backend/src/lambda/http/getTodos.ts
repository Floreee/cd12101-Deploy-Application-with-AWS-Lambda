import 'source-map-support/register'

import {APIGatewayProxyEvent, APIGatewayProxyResult, APIGatewayProxyHandler} from 'aws-lambda'
import {getTodos} from "../../businessLayer/todo";
import {createLogger} from "../../utils/logger";
import {getUserId} from "../utils";

const logger = createLogger('GetTodos-API')

export const handler: APIGatewayProxyHandler =
    async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {

        const userId = getUserId(event)

        logger.info('API Called for user = ' + userId)

        const todos = await getTodos(userId)

        logger.info('received todos from database', {'todos': todos})

        return {
            statusCode: 201,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': true
            },
            body: JSON.stringify({
                todos
            })
        }

    }
