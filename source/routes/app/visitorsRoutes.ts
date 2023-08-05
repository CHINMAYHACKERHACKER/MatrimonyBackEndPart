import express from 'express';
import controller from '../../controllers/app/visitors';

const router = express.Router();

// #region /api/app/visitors/getVisitors apidoc
/**
 * @api {post} /api/app/visitors/getVisitors Get  Proposals
 * @apiVersion 1.0.0
 * @apiName Get visitors
 * @apiDescription Get visitors
 * @apiGroup visitors - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Visitors",
 *          "recordList": [
 *              {
 *                  "id": 1,
 *                  "userId": 22,
 *                  "proposalUserId": 25,
 *                  "isAccepted": 1,
 *                  "isRejected": null,
 *                  "isActive": 1,
 *                  "isDelete": 0,
 *                  "createdDate": "2022-10-17T10:37:07.000Z",
 *                  "modifiedDate": "2022-10-17T10:37:07.000Z",
 *                  "createdBy": 22,
 *                  "modifiedBy": 22
 *              },
 *              {
 *                  "id": 3,
 *                  "userId": 22,
 *                  "proposalUserId": 24,
 *                  "isAccepted": 1,
 *                  "isRejected": null,
 *                  "isActive": 1,
 *                  "isDelete": 0,
 *                  "createdDate": "2022-10-18T10:25:01.000Z",
 *                  "modifiedDate": "2022-10-18T10:25:01.000Z",
 *                  "createdBy": 25,
 *                  "modifiedBy": 25
 *              }
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
router.post('/getVisitors', controller.getVisitors);

export = router;