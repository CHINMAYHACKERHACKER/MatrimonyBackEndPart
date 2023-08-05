import express from 'express';
import controller from '../../controllers/app/userBlock';

const router = express.Router();

// #region /api/app/block/getBlockUser apidoc
/**
 * @api {post} /api/app/block/getBlockUser Get Block User
 * @apiVersion 1.0.0
 * @apiName Get Block User
 * @apiDescription Get Block User
 * @apiGroup Block User - App
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
 *                  "userBlockId": 23,
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
router.post('/getBlockUser', controller.getBlockUser);

// #region /api/app/block/addRemoveBlock apidoc
/**
 * @api {post} /api/app/block/addRemoveBlock Remove Block User
 * @apiVersion 1.0.0
 * @apiName Remove Block User
 * @apiDescription Remove Block User
 * @apiGroup Block User - App
 * @apiParam  {Number}          userBlockId                Requires userBlockId of Favourites.
 * @apiParam  {boolean}          isBlockUser                Requires isBlockUser of Favourites.
 * @apiParamExample {json} Request-Example:
 *      {
 *          "userBlockId": 7,
 *          "isBlockUser": true
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
router.post('/addRemoveBlock', controller.addRemoveBlock);

export = router;
