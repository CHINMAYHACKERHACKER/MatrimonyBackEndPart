import express from 'express';
import controller from '../../controllers/app/userNotifications';

const router = express.Router();

// #region /api/app/notifications/getUserNotifications apidoc
/**
 * @api {post} /api/app/notifications/getUserNotifications Get Notifications
 * @apiVersion 1.0.0
 * @apiName Get Notifications
 * @apiDescription Get Notifications
 * @apiGroup Notifications - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *   {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Notifications Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "userId": 22,
 *                 "title": "dfvdgb",
 *                 "message": "dfvdcgvbdc",
 *                 "imageUrl": null,
 *                 "bodyJson": null,
 *                 "isRead": null,
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-11-04T12:55:11.000Z",
 *                 "modifiedDate": "2022-11-04T12:55:11.000Z",
 *                 "createdBy": 52,
 *                 "modifiedBy": 52
 *             }
 *         ],
 *         "totalRecords": 1,
 *         "token": ""
 *     }
 * @apiError (500) {JSON} Result message, apiName, apiType, fileName, functionName, lineNumber, typeName, stack.
 * @apiErrorExample {json} Error-500-Response:
 *     HTTP/1.1 500 ERROR
 *     {
 *          status: <error status code>,
 *          isDisplayMessage: <true/false>, // if the value is true then display message on screen
 *          message: <error message>,
 *          error: {
 *              apiName: <api name>,
 *              apiType: <api type>,
 *              fileName: <file name>,
 *              functionName: <function name>,
 *              lineNumber: <line number>,
 *              typeName: <type name>,
 *              stack: <stack>
 *          },
 *          value: <value if any>
 *     }
 */
// #endregion
router.post('/getUserNotifications', controller.getUserNotifications);

// #region /api/app/notifications/insertUserNotifications apidoc
/**
 * @api {post} /api/app/notifications/insertUserNotifications Insert Notifications
 * @apiVersion 1.0.0
 * @apiName Insert Notifications
 * @apiDescription Insert Notifications
 * @apiGroup Notifications - App
 * @apiParam  {String}          title                  Requires title of Notifications.
 * @apiParam  {String}          message                Requires message of Notifications.
 * @apiParamExample {json} Request-Example:
 * {
 *     "title": "Email"
 *     "message": "Check Email"
 * }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Insert Occupation",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 2,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "",
 *              "protocol41": true,
 *              "changedRows": 0
 *          },
 *          "totalRecords": 1,
 *          "token": ""
 *      }
 * @apiError (500) {JSON} Result message, apiName, apiType, fileName, functionName, lineNumber, typeName, stack.
 * @apiErrorExample {json} Error-500-Response:
 *     HTTP/1.1 500 ERROR
 *     {
 *          status: <error status code>,
 *          isDisplayMessage: <true/false>, // if the value is true then display message on screen
 *          message: <error message>,
 *          error: {
 *              apiName: <api name>,
 *              apiType: <api type>,
 *              fileName: <file name>,
 *              functionName: <function name>,
 *              lineNumber: <line number>,
 *              typeName: <type name>,
 *              stack: <stack>
 *          },
 *          value: <value if any>
 *     }
 */
// #endregion
router.post('/insertUserNotifications', controller.insertUserNotifications);

// #region /api/app/notifications/deleteUserNotifications apidoc
/**
 * @api {post} /api/app/notifications/deleteUserNotifications Delete Notifications
 * @apiVersion 1.0.0
 * @apiName Delete Notifications
 * @apiDescription Delete Notifications
 * @apiGroup Notifications - App
 * @apiParam  {Number}          id                Requires id of Notifications. (For remove single Notification)
 *  * @apiParamExample {json} Request-Example:
 * {
 *     "id": 3
 * }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *    {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Delete User Notifications",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 0,
 *             "serverStatus": 2,
 *             "warningCount": 0,
 *             "message": "",
 *             "protocol41": true,
 *             "changedRows": 0
 *         },
 *         "totalRecords": 1,
 *         "token": ""
 *     }
 * @apiError (500) {JSON} Result message, apiName, apiType, fileName, functionName, lineNumber, typeName, stack.
 * @apiErrorExample {json} Error-500-Response:
 *     HTTP/1.1 500 ERROR
 *     {
 *          status: <error status code>,
 *          isDisplayMessage: <true/false>, // if the value is true then display message on screen
 *          message: <error message>,
 *          error: {
 *              apiName: <api name>,
 *              apiType: <api type>,
 *              fileName: <file name>,
 *              functionName: <function name>,
 *              lineNumber: <line number>,
 *              typeName: <type name>,
 *              stack: <stack>
 *          },
 *          value: <value if any>
 *     }
 */
// #endregion
router.post('/deleteUserNotifications', controller.deleteUserNotifications);

export = router;