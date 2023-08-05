import express from 'express';
import controller from '../../controllers/admin/maritalStatus';

const router = express.Router();

// #region /api/admin/maritalStatus/getMaritalStatus apidoc
/**
 * @api {post} /api/admin/maritalStatus/getMaritalStatus Get Marital Status
 * @apiVersion 1.0.0
 * @apiName Get Marital Status
 * @apiDescription Get Marital Status
 * @apiGroup Marital Status - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Marital Status Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "name": "Married",
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-15T09:11:22.000Z",
 *                 "modifiedDate": "2022-10-15T09:11:22.000Z",
 *                 "createdBy": 5,
 *                 "modifiedBy": 5
 *             },
 *         ],
 *         "totalRecords": 4,
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
router.post('/getMaritalStatus', controller.getMaritalStatus);

// #region /api/admin/maritalStatus/insertUpdateMaritalStatus apidoc
/**
 * @api {post} /api/admin/maritalStatus/insertUpdateMaritalStatus Insert Update Marital Status
 * @apiVersion 1.0.0
 * @apiName Insert Update Marital Status
 * @apiDescription Insert Update Marital Status
  * @apiGroup Marital Status - Admin
 * @apiParam  {String}          name                Requires name of Marital Status.
 * @apiParam  {String}          id                  Requires id of Marital Status for Update.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "id": 1  // Require When edit Marital Status
 *           "name": "Married"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert Marital Status",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 1,
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
router.post('/insertUpdateMaritalStatus', controller.insertUpdateMaritalStatus);

// #region /api/admin/maritalStatus/activeInactiveMaritalStatus apidoc
/**
 * @api {post} /api/admin/maritalStatus/activeInactiveMaritalStatus Change Marital Status
 * @apiVersion 1.0.0
 * @apiName Change Marital Status
 * @apiDescription Change Marital Status
 * @apiGroup Marital Status - Admin
 * @apiParam  {Integer}         id                  Requires Marital Status Id.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "id": 1
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Change Marital Status",
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
router.post('/activeInactiveMaritalStatus', controller.activeInactiveMaritalStatus);

export = router;