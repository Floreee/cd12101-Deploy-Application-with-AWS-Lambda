import * as uuid from 'uuid'
import {TodoItem} from "../models/TodoItem";
import {createLogger} from "../utils/logger";
import {CreateTodoRequest} from "../requests/CreateTodoRequest";
import {UpdateTodoRequest} from "../requests/UpdateTodoRequest";
import {TodoAccess} from "../dataLayer/todoAccess";

const logger = createLogger('todo-business-layer')
const todoAccess = new TodoAccess()

export async function getTodos(userId: string): Promise<TodoItem[]> {

    logger.info('getTodos for ' + userId)
    return await todoAccess.getTodos(userId)
}

export async function createTodo(
    request: CreateTodoRequest,
    userId: string): Promise<TodoItem> {

    const itemId = uuid.v4()

    logger.info('Call Data-layer to create new Todo', {'Request': request, 'userId': userId})

    return await todoAccess.createTodo(
        {
            userId: userId,
            todoId: itemId,
            createdAt: new Date().toISOString(),
            name: request.name,
            dueDate: request.dueDate,
            done: false,
            attachmentUrl: ''
        }
    )
}

export async function updateTodo(
    request: UpdateTodoRequest,
    userId: string,
    todoId: string): Promise<TodoItem> {

    return await todoAccess.updateTodo(todoId, userId, request)
}

export async function deleteTodo(
    userId: string,
    todoId: string
): Promise<void> {
    return await todoAccess.deleteTodo(todoId, userId)
}

export async function getUploadUrl(todoId:string, userId:string): Promise<string> {
    return await todoAccess.generateUploadUrl(todoId, userId)
}
