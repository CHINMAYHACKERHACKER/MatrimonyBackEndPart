import express from 'express';
import controller from '../../controllers/admin/annualIncome';

const router = express.Router();

// #region /api/admin/annualIncome/getAnnualIncome apidoc
/**
 * @api {post} /api/admin/annualIncome/getAnnualIncome Get Annual Income
 * @apiVersion 1.0.0
 * @apiName Get Annual Income
 * @apiDescription Get Annual Income
 * @apiGroup Annual Income - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Annual Income Successfully",
 *          "recordList": [
 *              {
 *                  "id": 1,
 *                  "value": "50000",
 *                  "isActive": 1,
 *                  "isDelete": 0,
 *                  "createdDate": "2022-10-14T06:36:56.000Z",
 *                  "modifiedDate": "2022-10-14T06:36:56.000Z",
 *                  "createdBy": 6,
 *                  "modifiedBy": 6
 *              },...
 *          ],
 *          "totalRecords": 12,
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
router.post('/getAnnualIncome', controller.getAnnualIncome);

// #region /api/admin/annualIncome/insertUpdateAnnualIncome apidoc
/**
 * @api {post} /api/admin/annualIncome/insertUpdateAnnualIncome Insert Update Annual Income
 * @apiVersion 1.0.0
 * @apiName Insert Update Annual Income
 * @apiDescription Insert Update Annual Income
 * @apiGroup Annual Income - Admin
 * @apiParam  {String}          value                Requires value of Annual Income.
 * @apiParam  {String}          id                   Requires id of Annual Income for Update only.
 * @apiParamExample {json} Request-Example:
 * { 
 *      "id": 13  // Require when Edit Annual Income
 *      "value": "50000"
 * }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert Annual Income",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 13,
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
router.post('/insertUpdateAnnualIncome', controller.insertUpdateAnnualIncome);

// #region /api/admin/annualIncome/activeInactiveAnnualIncome apidoc
/**
 * @api {post} /api/admin/annualIncome/activeInactiveAnnualIncome Change Annual Income
 * @apiVersion 1.0.0
 * @apiName Change Annual Income
 * @apiDescription Change Annual Income
 * @apiGroup Annual Income - Admin
 * @apiParam  {Integer}         id                  Requires Annual Income Id.
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
 *         "message": "Change Annual Income Status",
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
router.post('/activeInactiveAnnualIncome', controller.activeInactiveAnnualIncome);

export = router;