import express from 'express';
import controller from '../../controllers/admin/religion';

const router = express.Router();

// #region /api/admin/religion/getReligion apidoc
/**
 * @api {post} /api/admin/religion/getReligion Get Religion
 * @apiVersion 1.0.0
 * @apiName Get Religion
 * @apiDescription Get Religion
 * @apiGroup Religion - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Religion Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "name": "Hindu",
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-15T10:14:14.000Z",
 *                 "modifiedDate": "2022-10-15T10:14:14.000Z",
 *                 "createdBy": 5,
 *                 "modifiedBy": 5
 *             },....
 *         ],
 *         "totalRecords": 9,
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
router.post('/getReligion', controller.getReligion);

// #region /api/admin/religion/insertUpdateReligion apidoc
/**
 * @api {post} /api/admin/religion/insertUpdateReligion insert update Religion
 * @apiVersion 1.0.0
 * @apiName insert update Religion
 * @apiDescription insert update Religion
 * @apiGroup Religion - Admin
 * @apiParam  {String}          name                Requires name of Religion.
 * @apiParam  {String}          id                  Requires id of Religion for Update.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "id": 1  // Require When edit Religion
 *           "name": "Hindu"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert Religion",
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
router.post('/insertUpdateReligion', controller.insertUpdateReligion);

// #region /api/admin/religion/activeInactiveReligion apidoc
/**
 * @api {post} /api/admin/religion/activeInactiveReligion Change Religion
 * @apiVersion 1.0.0
 * @apiName Change Religion
 * @apiDescription Change Religion
 * @apiGroup Religion - Admin
 * @apiParam  {Integer}         id                  Requires Religion Id.
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
 *         "message": "Change Religion Status",
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
router.post('/activeInactiveReligion', controller.activeInactiveReligion);

export = router;