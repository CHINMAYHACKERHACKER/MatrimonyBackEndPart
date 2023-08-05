import express from 'express';
import controller from '../../controllers/admin/occupation';

const router = express.Router();

// #region /api/admin/occupation/getOccupation apidoc
/**
 * @api {post} /api/admin/occupation/getOccupation Get Occupation
 * @apiVersion 1.0.0
 * @apiName Get Occupation
 * @apiDescription Get Occupation
 * @apiGroup Occupation - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Occupation Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "parentId": null,
 *                 "name": "Teacher",
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
router.post('/getOccupation', controller.getOccupation);

// #region /api/admin/occupation/insertUpdateOccupation apidoc
/**
 * @api {post} /api/admin/occupation/insertUpdateOccupation insert update Occupation
 * @apiVersion 1.0.0
 * @apiName insert update Occupation
 * @apiDescription insert update Occupation
 * @apiGroup Occupation - Admin
 * @apiParam  {String}          name                Requires name of Occupation.
 * @apiParam  {String}          id                  Requires id of Occupation for Update.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "id": 2  // Require When edit Occupation
 *           "name": "Doctor"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert Occupation",
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
router.post('/insertUpdateOccupation', controller.insertUpdateOccupation);

// #region /api/admin/occupation/activeInactiveOccupation apidoc
/**
 * @api {post} /api/admin/occupation/activeInactiveOccupation Change Occupation
 * @apiVersion 1.0.0
 * @apiName Change Occupation
 * @apiDescription Change Occupation
 * @apiGroup Occupation - Admin
 * @apiParam  {Integer}         id                  Requires Occupation Id.
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
 *         "message": "Change Occupation Status",
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
router.post('/activeInactiveOccupation', controller.activeInactiveOccupation);

export = router;