import express from 'express';
import controller from '../../controllers/admin/timeDuration';

const router = express.Router();

// #region /api/admin/timeDuration/getTimeDuration apidoc
/**
 * @api {post} /api/admin/timeDuration/getTimeDuration Get Time Duration
 * @apiVersion 1.0.0
 * @apiName Get Time Duration
 * @apiDescription Get Time Duration
 * @apiGroup Time Duration - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Time Duration Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "value": "3 Month",
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-13T11:02:56.000Z",
 *                 "modifiedDate": "2022-10-13T11:02:56.000Z",
 *                 "createdBy": 6,
 *                 "modifiedBy": 6
 *             },.....
 *         ],
 *         "totalRecords": 2,
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
router.post('/getTimeDuration', controller.getTimeDuration);

// #region /api/admin/timeDuration/insertUpdateTimeDuration apidoc
/**
 * @api {post} /api/admin/timeDuration/insertUpdateTimeDuration InsertUpdate Time Duration
 * @apiVersion 1.0.0
 * @apiName InsertUpdate Time Duration
 * @apiDescription InsertUpdate Time Duration
 * @apiGroup Time Duration - Admin
 * @apiParam  {Integer}                 id                      Requires Time Duration Id only when Edit else not send.
 * @apiParam  {string}                  value                   Requires Time Duration value.
 * @apiParamExample {json} Request-Example:
 *      {
 *           "id": 1,  //Requires Time Duration Id only when Edit else not send.
 *           "value": "3 Month"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:                                    
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert/Update Time Duration",
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
router.post('/insertUpdateTimeDuration', controller.insertUpdateTimeDuration);

// #region /api/admin/timeDuration/activeInactiveTimeDuration apidoc
/**
 * @api {post} /api/admin/timeDuration/activeInactiveTimeDuration Change Time Duration Status
 * @apiVersion 1.0.0
 * @apiName Change Time Duration
 * @apiDescription Change Time Duration
 * @apiGroup Time Duration - Admin
 * @apiParam  {Integer}         id                  Requires Time Duration Id.
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
 *         "message": "Change Time Duration Status",
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
router.post('/activeInactiveTimeDuration', controller.activeInactiveTimeDuration);

// #region /api/admin/timeDuration/deleteTimeDuration apidoc
/**
 * @api {post} /api/admin/timeDuration/deleteTimeDuration Delete Time Duration
 * @apiVersion 1.0.0
 * @apiName Delete Time Duration
 * @apiDescription Delete Time Duration
 * @apiGroup Time Duration - Admin
 * @apiParam  {Integer}         id                  Requires Time Duration Id.
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
 *         "message": "Delete Time Duration",
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
router.post('/deleteTimeDuration', controller.deleteTimeDuration);

export = router;