import express from 'express';
import controller from '../../controllers/admin/systemFlags';

const router = express.Router();

// #region /api/admin/systemflags/getAdminSystemFlag apidoc
/**
 * @api {post} /api/admin/systemflags/getAdminSystemFlag Get System Flag
 * @apiVersion 1.0.0
 * @apiName Get  System Flag
 * @apiDescription Get  System Flag
 * @apiGroup  System Flag - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get System flag successfully",
 *         "recordList": [
 *             {
 *                 "flagGroupId": 1,
 *                 "flagGroupName": "General",
 *                 "parentFlagGroupId": null,
 *                 "systemFlags": [
 *                     {
 *                         "id": 7,
 *                         "flagGroupId": 1,
 *                         "valueTypeId": 1,
 *                         "name": "welcomeText",
 *                         "displayName": "Welcome Text",
 *                         "value": "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat",
 *                         "defaultValue": "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat",
 *                         "valueList": null,
 *                         "description": null,
 *                         "label": null,
 *                         "autoRender": 1,
 *                         "isActive": 1,
 *                         "isDelete": 0,
 *                         "createdDate": "2022-10-21T04:34:45.000Z",
 *                         "modifiedDate": "2022-10-21T04:34:45.000Z",
 *                         "createdBy": 1,
 *                         "modifiedBy": 1,
 *                         "flagGroupName": "General",
 *                         "valueTypeName": "Text"
 *                     }
 *                 ],
 *                 "group": [
 *                     {
 *                         "flagGroupId": 2,
 *                         "flagGroupName": "Email Crendential",
 *                         "parentFlagGroupId": 1,
 *                         "systemFlags": [
 *                             {
 *                                 "id": 1,
 *                                 "flagGroupId": 2,
 *                                 "valueTypeId": 6,
 *                                 "name": "noReplyEmail",
 *                                 "displayName": "Sender Email Id",
 *                                 "value": "nativeserver01@gmail.com",
 *                                 "defaultValue": "nativeserver01@gmail.com",
 *                                 "valueList": null,
 *                                 "description": null,
 *                                 "label": null,
 *                                 "autoRender": 1,
 *                                 "isActive": 1,
 *                                 "isDelete": 0,
 *                                 "createdDate": "2022-10-20T10:35:23.000Z",
 *                                 "modifiedDate": "2022-10-20T10:35:23.000Z",
 *                                 "createdBy": 1,
 *                                 "modifiedBy": 1,
 *                                 "flagGroupName": "Email Crendential",
 *                                 "valueTypeName": "Email"
 *                             },....
 *                         ]
 *                     }
 *                 ]
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
router.post('/getAdminSystemFlag', controller.getAdminSystemFlag);

// #region /api/admin/systemflags/updateSystemFlagByName apidoc
/**
 * @api {post} /api/admin/systemflags/updateSystemFlagByName Update System Flag List
 * @apiVersion 1.0.0
 * @apiName Update System Flag List
 * @apiDescription Update System Flag List
 * @apiGroup System Flag - Admin
 * @apiParam  {Array}          valueList                Requires Array List of value.
 * @apiParam  {Array}          nameList                 Requires Array List of System Flag Name.
 * @apiParamExample {json} Request-Example:
 *      {
 *          "nameList": [ "noReplyEmail", "noReplyPassword", "noReplyName"],
 *          "valueList": [ "nativeserver02@gmail.com", "Info@2021", "Matrimony Team"]
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Update Syatem Flag",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 0,
 *             "serverStatus": 34,
 *             "warningCount": 0,
 *             "message": "(Rows matched: 1  Changed: 0  Warnings: 0",
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
router.post('/updateSystemFlagByName', controller.updateSystemFlagByName);

export = router;