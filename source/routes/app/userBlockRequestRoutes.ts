import express from 'express';
import controller from '../../controllers/app/userBlockRequest';

const router = express.Router();

// #region /api/app/userBlockRequest/getUserBlockRequest apidoc
/**
 * @api {post} /api/app/userBlockRequest/getUserBlockRequest Get User Block Request
 * @apiVersion 1.0.0
 * @apiName Get User lock Request
 * @apiDescription Get User Block Request
 * @apiGroup User Block Request - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Proposals Got By me Successfully",
 *          "recordList": [
 *              {
 *                  "id": 7,
 *                  "userId": 52,
 *                  "blockRequestUserId": 23,
 *                  "reason": "undefined",
 *                  "status": null,
 *                  "isActive": 1,
 *                  "isDelete": 0,
 *                  "createdDate": "2022-11-03T10:35:31.000Z",
 *                  "modifiedDate": "2022-11-03T10:35:31.000Z",
 *                  "createdBy": 52,
 *                  "modifiedBy": 52,
 *                  "firstName": "Bhumi",
 *                  "lastName": "Gothi",
 *                  "gender": "Female",
 *                  "email": "bhumi123@gmail.com",
 *                  "contactNo": "4631867656",
 *                  "imageUrl": null
 *              },...
 *          ],
 *          "totalRecords": 2,
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
router.post('/getUserBlockRequest', controller.getUserBlockRequest);

// #region /api/app/userBlockRequest/insertUserBlockRequest apidoc
/**
 * @api {post} /api/app/userBlockRequest/insertUserBlockRequest Insert Update User Block Request
 * @apiVersion 1.0.0
 * @apiName Insert User Block Request
 * @apiDescription Insert User Block Request
 * @apiGroup User Block Request - App
 * @apiParam  {Number}          blockRequestUserId         Requires blockRequestUserId of UserBlockRequest.
 * @apiParamExample {json} Request-Example:
 *      {
 *          "blockRequestUserId": "24",
 *          "reason": "abc"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *    {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert User Block Request",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 8,
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
router.post('/insertUserBlockRequest', controller.insertUserBlockRequest);

// #region /api/app/userBlockRequest/removeUserBlockRequest apidoc
/**
 * @api {post} /api/app/userBlockRequest/removeUserBlockRequest Remove User Block Request
 * @apiVersion 1.0.0
 * @apiName Remove User Block Request
 * @apiDescription Remove User Block Request
 * @apiGroup User Block Request - App
 * @apiParam  {Number}          id                Requires Id of Favourites.
 * @apiParamExample {json} Request-Example:
 *      {
 *          "id": 7
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Remove User Block Request",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
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
router.post('/removeUserBlockRequest', controller.removeUserBlockRequest);

export = router;