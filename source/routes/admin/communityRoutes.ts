import express from 'express';
import controller from '../../controllers/admin/community';

const router = express.Router();

// #region /api/admin/community/getCommunity apidoc
/**
 * @api {post} /api/admin/community/getCommunity Get Community
 * @apiVersion 1.0.0
 * @apiName Get Community
 * @apiDescription Get Community
 * @apiGroup Community - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Community Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "name": "Singh",
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-14T07:04:39.000Z",
 *                 "modifiedDate": "2022-10-14T07:04:39.000Z",
 *                 "createdBy": 6,
 *                 "modifiedBy": 6
 *             },....
 *         ],
 *         "totalRecords": 11,
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
router.post('/getCommunity', controller.getCommunity);

// #region /api/admin/community/insertUpdateCommunity apidoc
/**
 * @api {post} /api/admin/community/insertUpdateCommunity insert update Community
 * @apiVersion 1.0.0
 * @apiName insert update Community
 * @apiDescription insert update Community
  * @apiGroup Community - Admin
 * @apiParam  {String}          name                Requires name of Community.
 * @apiParam  {String}          id                  Requires id of Community for Update.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "id": 2  // Require When edit community
 *           "name": "Patel"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert Community",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 2,
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
router.post('/insertUpdateCommunity', controller.insertUpdateCommunity);

// #region /api/admin/community/activeInactiveCommunity apidoc
/**
 * @api {post} /api/admin/community/activeInactiveCommunity Change Community
 * @apiVersion 1.0.0
 * @apiName Change Community
 * @apiDescription Change Community
 * @apiGroup Community - Admin
 * @apiParam  {Integer}         id                  Requires Community Id.
 * @apiParamExample {json} Request-Example:
 *    {
 *        "id": 2
 *    }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Change Community Status",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 0,
 *             "serverStatus": 2,
 *             "warningCount": 1,
 *             "message": "(Rows matched: 1  Changed: 1  Warnings: 1",
 *             "protocol41": true,
 *             "changedRows": 1
 *         },
 *         "totalRecords": 1,
 *         "token": ""
 *     }
 * @apiError (500) {JSON} Result message, apiName, apiType, fileName, functionName, lineNumber, typeName, stack.
 * @apiErrorExample {json} Error-500-Response:
 *     HTTP/1.1 500 ERROR
 *    {
 *         "status": 400,
 *         "isDisplayMessage": true,
 *         "message": "Error While Change Community Status",
 *         "value": "",
 *         "error": {
 *             "apiName": "",
 *             "apiType": "",
 *             "fileName": "trace is not available",
 *             "functionName": "trace is not available",
 *             "functionErrorMessage": "community.insertUpdateCommunity() Error : Error: Error While Change Community Status",
 *             "lineNumber": "trace is not available",
 *             "typeName": "trace is not available",
 *             "stack": "Error stack is not available"
 *         }
 *     }
 */
// #endregion
router.post('/activeInactiveCommunity', controller.activeInactiveCommunity);

export = router;