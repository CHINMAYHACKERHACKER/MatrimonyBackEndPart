import express from 'express';
import controller from '../../controllers/admin/userBlockRequest';

const router = express.Router();

// #region /api/admin/userBlockRequest/getUserBlockRequest apidoc
/**
 * @api {post} /api/admin/userBlockRequest/getUserBlockRequest Get User Block Request
 * @apiVersion 1.0.0
 * @apiName Get User lock Request
 * @apiDescription Get User Block Request
 * @apiGroup User Block Request - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get User Block Request Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "userId": 22,
 *                 "blockRequestUserId": 24,
 *                 "reason": "Do not disturb",
 *                 "status": 1,
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-19T06:57:09.000Z",
 *                 "modifiedDate": "2022-10-19T06:57:09.000Z",
 *                 "createdBy": 22,
 *                 "modifiedBy": 22
 *             },....
 *      ],
 *         "totalRecords": 6,
 *         "token": 
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
router.post('/getUserBlockRequest', controller.getUserBlockRequest);

// #region /api/admin/userBlockRequest/updateUserBlockRequest apidoc
/**
 * @api {post} /api/admin/userBlockRequest/updateUserBlockRequest Update User Block Request
 * @apiVersion 1.0.0
 * @apiName Update User Block Request
 * @apiDescription Update User Block Request
 * @apiGroup User Block Request - Admin
 * @apiParam  {Number}          id                     Requires id of UserBlockRequest.
 * @apiParam  {Boolean}         status                 Requires status of UserBlockRequest.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "id": 4,
 *         "status": false
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Update User Block Request",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 0,
 *             "serverStatus": 2,
 *             "warningCount": 0,
 *             "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
 *             "protocol41": true,
 *             "changedRows": 1
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
router.post('/updateUserBlockRequest', controller.updateUserBlockRequest);

export = router;