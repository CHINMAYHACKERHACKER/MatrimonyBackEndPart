import express from 'express';
import controller from '../../controllers/admin/education';

const router = express.Router();

// #region /api/admin/education/getEducation apidoc
/**
 * @api {post} /api/admin/education/getEducation Get Education
 * @apiVersion 1.0.0
 * @apiName Get Education
 * @apiDescription Get Education
 * @apiGroup Education - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Education Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "parentId": null,
 *                 "name": "ME",
 *                 "isActive": 0,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-15T07:27:45.000Z",
 *                 "modifiedDate": "2022-10-15T07:27:45.000Z",
 *                 "createdBy": 6,
 *                 "modifiedBy": 6
 *             },....
 *         ],
 *         "totalRecords": 7,
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
router.post('/getEducation', controller.getEducation);

// #region /api/admin/education/insertUpdateEducation apidoc
/**
 * @api {post} /api/admin/education/insertUpdateEducation insert update Education
 * @apiVersion 1.0.0
 * @apiName insert update Education
 * @apiDescription insert update Education
  * @apiGroup Education - Admin
 * @apiParam  {String}          name                Requires name of Education.
 * @apiParam  {String}          id                  Requires id of Education for Update.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "id": 4  // Require When edit Education
 *           "name": "BBA"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert Education",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 4,
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
router.post('/insertUpdateEducation', controller.insertUpdateEducation);

// #region /api/admin/education/activeInactiveEducation apidoc
/**
 * @api {post} /api/admin/education/activeInactiveEducation Change Education
 * @apiVersion 1.0.0
 * @apiName Change Education
 * @apiDescription Change Education
 * @apiGroup Education - Admin
 * @apiParam  {Integer}         id                  Requires Education Id.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "id": 4
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Change Education Status",
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
router.post('/activeInactiveEducation', controller.activeInactiveEducation);

export = router;