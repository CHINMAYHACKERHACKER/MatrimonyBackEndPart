import express from 'express';
import controller from '../../controllers/app/package';

const router = express.Router();

// #region /api/app/package/getpackage apidoc
/**
 * @api {post} /api/app/package/getpackage Get Package
 * @apiVersion 1.0.0
 * @apiName Get Package
 * @apiDescription Get Package
 * @apiGroup Package - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Package Successfully",
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
router.post('/getpackage', controller.getpackage);

// #region /api/app/package/savePremiumAccount apidoc
/**
 * @api {post} /api/app/package/savePremiumAccount Save Premium Account
 * @apiVersion 1.0.0
 * @apiName Save Premium Account
 * @apiDescription Save Premium Account
 * @apiGroup Package - App
 * @apiParam  {String}          aboutMe                         User aboutMe.
 * @apiParamExample {json} Request-Example:
 * {
 *     "packageId": "2",
 *     "packageDurationId": "4",
 *     "startDate": "2023-03-21 14:50:03",
 *     "endate":  "2023-03-21 14:50:03",
 *     "netAmount": "5000",
 *     "purchaseDate": "2023-03-21 14:50:03"
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Save Premium Account Successfully",
 *         "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "(Rows matched: 1  Changed: 0  Warnings: 0",
 *              "protocol41": true,
 *              "changedRows": 0
 *          },
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
router.post('/savePremiumAccount', controller.savePremiumAccount);
router.post('/getPackageByUserId',controller.getPackageByUserId);

export = router;