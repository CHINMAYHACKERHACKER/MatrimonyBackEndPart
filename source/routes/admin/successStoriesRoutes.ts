import express from 'express';
import controller from '../../controllers/admin/successStories';

const router = express.Router();

// #region /api/admin/successStories/getSuccessStories apidoc
/**
 * @api {post} /api/admin/successStories/getSuccessStories Get Success Stories
 * @apiVersion 1.0.0
 * @apiName Get Success Stories
 * @apiDescription Get Success Stories
 * @apiGroup Success Stories - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Success Stories Successfully",
 *          "recordList": [
 *             {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Success Stories Successfully",
 *          "recordList": [
 *              {
 *                  "id": 1
 *                  "userId": 22,
 *                  "partnerUserId": 23,
 *                  "imageId": null,
 *                  "maritalStatus": married,
 *                  "isActive": "1",
 *                  "isDelete": "0",
 *                  "createdDate": "2022-10-19 10:49:52",
 *                  "modifiedDate": "2022-10-19 10:49:52",
 *                  "createdBy": "22",
 *                  "modifiedBy": "22",
 *                  "imageUrl": null
 *              },....
 *        ],
 *          "totalRecords": 4,
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
router.post('/getSuccessStories', controller.getSuccessStories);

// #region /api/admin/successStories/activeInactiveSuccessStories apidoc
/**
 * @api {post} /api/admin/successStories/activeInactiveSuccessStories Change Success Stories Status
 * @apiVersion 1.0.0
 * @apiName Change Success Stories Status
 * @apiDescription Change Success Stories Status
 * @apiGroup Success Stories - Admin
 * @apiParam  {Number}          id                      Requires id of Success Stories.
 * @apiParamExample {json} Request-Example:
 * {
 *      "id": "1"
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *    {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert Success Stories Successfully",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 14,
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
router.post('/activeInactiveSuccessStories', controller.activeInactiveSuccessStories);

export = router;
