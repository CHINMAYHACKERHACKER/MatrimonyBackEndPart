import express from 'express';
import controller from '../../controllers/admin/premiumAccountType';

const router = express.Router();

// #region /api/admin/premiumAccountType/getPremiumAccountType apidoc
/**
 * @api {post} /api/admin/premiumAccountType/getPremiumAccountType Get Premium Account Type
 * @apiVersion 1.0.0
 * @apiName Get Premium Account Type
 * @apiDescription Get Premium Account Type
 * @apiGroup Premium Account Type - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Premium Account Type Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "name": "dfcdxv",
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-13T11:02:56.000Z",
 *                 "modifiedDate": "2022-10-13T11:02:56.000Z",
 *                 "createdBy": 6,
 *                 "modifiedBy": 6
 *             },.....
 *         ],
 *         "totalRecords": 14,
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
router.post('/getPremiumAccountType', controller.getPremiumAccountType);

// #region /api/admin/premiumAccountType/insertUpdatePremiumAccountType apidoc
/**
 * @api {post} /api/admin/premiumAccountType/insertUpdatePremiumAccountType InsertUpdate Premium Account Type
 * @apiVersion 1.0.0
 * @apiName InsertUpdate Premium Account Type
 * @apiDescription InsertUpdate Premium Account Type
 * @apiGroup Premium Account Type - Admin
 * @apiParam  {Integer}         id                  Requires Premium Account Type Id.
 * @apiParam  {string}         name                  Requires Premium Account Type name.
 * @apiParamExample {json} Request-Example:
 *      {
 *           "id": 2,
 *           "name": "sdfdfb"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert/Update Premium Account Type Status",
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
router.post('/insertUpdatePremiumAccountType', controller.insertUpdatePremiumAccountType);

// #region /api/admin/premiumAccountType/activeInactivePremiumAccountType apidoc
/**
 * @api {post} /api/admin/premiumAccountType/activeInactivePremiumAccountType Change Premium Account Type
 * @apiVersion 1.0.0
 * @apiName Change Premium Account Type
 * @apiDescription Change Premium Account Type
 * @apiGroup Premium Account Type - Admin
 * @apiParam  {Integer}         id                  Requires Premium Account Type Id.
 * @apiParamExample {json} Request-Example:
 *      {
 *           "id": 2
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Change Premium Account Type Status",
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
router.post('/activeInactivePremiumAccountType', controller.activeInactivePremiumAccountType);

export = router;