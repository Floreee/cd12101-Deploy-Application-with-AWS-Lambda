import * as AWS from "aws-sdk";
//import * as AWSXRay from 'aws-xray-sdk-core'
//import AWSXRay from "aws-xray-sdk-core";
import {DocumentClient} from 'aws-sdk/clients/dynamodb';
import {TodoItem} from "../models/TodoItem";
import {TodoUpdate} from "../models/TodoUpdate";
import {createLogger} from "../utils/logger";

//const XAWS = AWSXRay.captureAWS(AWS)
const XAWS = require('aws-xray-sdk') 
const logger = createLogger('todoAccess')
const bucket = process.env.BUCKET_NAME
const urlExpiration = process.env.SIGNED_URL_EXPIRATION

/**
 * Enable usage of local Dynamo-DB
 */
function createDynamoDBClient() {
    if (process.env.IS_OFFLINE) {
        logger.info('Creating a local DynamoDB instance')
        return new XAWS.DynamoDB.DocumentClient({
            region: 'localhost',
            endpoint: 'http://localhost:8000'
        })
    }

    return new AWS.DynamoDB.DocumentClient()
}

function createS3Client() {
    if (process.env.IS_OFFLINE) {
        logger.info('Creating local S3 instance')
        return new XAWS.S3({
            s3ForcePathStyle: true,
            accessKeyId: 'S3RVER', // This specific key is required when working offline
            secretAccessKey: 'S3RVER',
            endpoint: new AWS.Endpoint('http://localhost:4569'),
        })
    }
    logger.info('Creating S3 instance')
    return new AWS.S3({signatureVersion: 'v4'})
}

/**
 * Data Logic to access create, delete and update
 * 'todo_items in Dynamo-Database
 */

export class TodoAccess {

    constructor(
        private readonly docClient: DocumentClient = createDynamoDBClient(),
        private readonly s3Client = createS3Client(),
        private readonly todoTable = process.env.TODOS_TABLE,
        private readonly indexName = process.env.INDEX_NAME) {
    }

    /**
     * Fetch all todos for a user
     * @param userId = id of the user
     */
    async getTodos(userId: string): Promise<TodoItem[]> {
        logger.info('get ToDos from database', {'userId': userId, 'table': this.todoTable})

        const result = await this.docClient.query({
            TableName: this.todoTable,
            IndexName: this.indexName,
            KeyConditionExpression: 'userId= :userId',
            ExpressionAttributeValues: {':userId': userId}
        }).promise()

        return result.Items as TodoItem[];
    }

    /**
     * create a new todo_item
     * @param item = new todo_item
     */
    async createTodo(item: TodoItem): Promise<TodoItem> {
        logger.info('create ToDos in database', {...item, 'Table': this.todoTable})
        const params = {
            TableName: this.todoTable,
            Item: {
                ...item
            }
        }
        const result = await this.docClient.put(params).promise()
        logger.info('Response from put', {'response': result.$response.data, 'error': result.$response.error})
        return item
    }

    /**
     * update an existing item of a user
     * @param todoId = id of the item to be updated
     * @param todoUpdate = object, with updated data (name, duedate, done)
     * @param userId = id of user, who owns the item
     */
    async updateTodo(todoId: string, userId: string, todoUpdate: TodoUpdate): Promise<TodoItem> {
        logger.info('update ToDo in database',
            {'todoId': todoId, 'userId': userId, 'todoUpdate': todoUpdate})

        const item = await this.docClient.update(
            {
                TableName: this.todoTable,
                Key: {
                    'todoId': todoId,
                    'userId': userId
                },
                UpdateExpression: "set #name = :n, #dueDate=:dd, #done=:d",
                ExpressionAttributeValues: {
                    ":n": todoUpdate.name,
                    ":dd": todoUpdate.dueDate,
                    ":d": todoUpdate.done
                },
                ExpressionAttributeNames: {
                    '#name': 'name',
                    '#dueDate': 'dueDate',
                    '#done': 'done'
                },
                ReturnValues: "UPDATED_NEW"
            }
        ).promise()

        return item.$response.data as TodoItem
    }

    /**
     * delete a todo_item
     * @param todoId = id of the todo_item
     */
    async deleteTodo(todoId: String, userId: string): Promise<void> {
        logger.info('delete ToDos in database', {'todoId': todoId, 'userId': userId})
        await this.docClient.delete(
            {
                TableName: this.todoTable,
                Key: {
                    'todoId': todoId,
                    'userId': userId
                }
            }).promise()
    }

    /**
     * generates an upload-url in AWS-S3
     * an update todo item
     */
    async generateUploadUrl(todoId: string, userId: string): Promise<string> {

        logger.info('get AttachmentUrl', {'bucket': bucket, 'todoId': todoId, 'userId': userId})

        //get the download-url
        const attachmentUrl = await this.s3Client.getSignedUrl('getObject', {
                Bucket: bucket,
                Key: todoId
            }
        )

        logger.info('received AttachmentUrl', {'url': attachmentUrl})

        // update the to-do item
        try {
            await this.docClient.update({
                TableName: this.todoTable,
                Key: {
                    'todoId': todoId,
                    'userId': userId
                },
                UpdateExpression: "set #url = :url",
                ExpressionAttributeValues: {
                    ":url": attachmentUrl
                },
                ExpressionAttributeNames: {
                    '#url': 'attachmentUrl'
                }
            }).promise()
        } catch (err) {
            logger.error('there was an error updating todo-item', {'error': err})
        }

        logger.info('get UploadUrl', {'bucket': bucket, 'todoId': todoId, 'expires': urlExpiration})


        return this.s3Client.getSignedUrl('putObject', {
            Bucket: bucket,
            Key: todoId,
            Expires: parseInt(urlExpiration)
        })
    }
}
