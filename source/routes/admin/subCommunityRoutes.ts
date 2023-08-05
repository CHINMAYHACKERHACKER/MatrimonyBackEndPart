import express from 'express';
import controller from '../../controllers/admin/subComunity';

const router = express.Router();

// #region /api/admin/subCommunity/getSubCommunity apidoc
/**
 * @api {post} /api/admin/subCommunity/getSubCommunity Get Sub Community
 * @apiVersion 1.0.0
 * @apiName Get Sub Community
 * @apiDescription Get Sub Community
 * @apiGroup Sub Community - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Sub Community Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "communityId": null,
 *                 "name": "Brahmin",
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-15T10:18:35.000Z",
 *                 "modifiedDate": "2022-10-15T10:18:35.000Z",
 *                 "createdBy": 5,
 *                 "modifiedBy": 5
 *             },....
 *         ],
 *         "totalRecords": 3,
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
router.post('/getSubCommunity', controller.getSubCommunity);

// #region /api/admin/subCommunity/insertUpdateSubCommunity apidoc
/**
 * @api {post} /api/admin/subCommunity/insertUpdateSubCommunity insert update Sub Community
 * @apiVersion 1.0.0
 * @apiName insert update Sub Community
 * @apiDescription insert update Sub Community
 * @apiGroup Sub Community - Admin
 * @apiParam  {String}          name                Requires name of Sub Community.
 * @apiParam  {String}          id                  Requires id of Sub Community for Update.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "id": 1  // Require When edit Sub Community
 *           "name": "Brahmin"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert Sub Community",
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
router.post('/insertUpdateSubCommunity', controller.insertUpdateSubCommunity);

// #region /api/admin/subCommunity/activeInactiveSubCommunity apidoc
/**
 * @api {post} /api/admin/subCommunity/activeInactiveSubCommunity Change Sub Community
 * @apiVersion 1.0.0
 * @apiName Change Sub Community
 * @apiDescription Change Sub Community
 * @apiGroup Sub Community - Admin
 * @apiParam  {Integer}         id                  Requires Sub Community Id.
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
router.post('/activeInactiveSubCommunity', controller.activeInactiveSubCommunity);

export = router;