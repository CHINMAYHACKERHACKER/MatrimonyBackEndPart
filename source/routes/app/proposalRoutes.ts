import express from 'express';
import controller from '../../controllers/app/proposal';

const router = express.Router();

// #region /api/app/proposals/getProposalsGotByMe apidoc
/**
 * @api {post} /api/app/proposals/getProposalsGotByMe Get Proposals Got By Me
 * @apiVersion 1.0.0
 * @apiName Get Proposals Got By Me
 * @apiDescription Get Proposals Got By Me
 * @apiGroup Proposals - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Proposals Got By me Successfully",
 *          "recordList": [
 *              {
 *                  "id": 1
 *                  "userId": 22,
 *                  "proposalUserId": 23,
 *                  "status": null,
 *                  "firstName": "Rahul",
 *                  "lastName": "Gamit",
 *                  "gender": "Male",
 *                  "email": "rahul123@gmail.com",
 *                  "contactNo": "3265478912",
 *                  "image": "content/user/22/26.jpeg",
 *                  "isBlockByMe": 0,
 *                  "isBlockByOther": 0,
 *                  "createdDate": "2022-10-18T10:24:55.000Z",
 *                  "occupation": "Doctor"
 *                  "age": "28"
 *                  "birthDate": "28"
 *                  "cityName": "Surat"
 *              },....
 *        ],
 *          "totalRecords": 4,
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
router.post('/getProposalsGotByMe', controller.getProposalsGotByMe);

// #region /api/app/proposals/getProposalsSendByMe apidoc
/**
 * @api {post} /api/app/proposals/getProposalsSendByMe Get Proposals Send By Me
 * @apiVersion 1.0.0
 * @apiName Get Proposals Send By Me
 * @apiDescription Get Proposals Send By Me
 * @apiGroup Proposals - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Proposals Send by me Successfully",
 *          "recordList": [
 *              {
 *                  "id": 1
 *                  "userId": 22,
 *                  "proposalUserId": 23,
 *                  "status": null,
 *                  "firstName": "Rahul",
 *                  "lastName": "Gamit",
 *                  "gender": "Male",
 *                  "email": "rahul123@gmail.com",
 *                  "contactNo": "3265478912",
 *                  "image": "content/user/22/26.jpeg",
 *                  "isBlockByMe": 0,
 *                  "isBlockByOther": 0,
 *                  "createdDate": "2022-10-18T10:24:55.000Z",
 *                  "occupation": "Doctor"
 *                  "age": "28"
 *                  "birthDate": "28"
 *                  "cityName": "Surat"
 *              },....
 *       ],
 *          "totalRecords": 3,
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
router.post('/getProposalsSendByMe', controller.getProposalsSendByMe);

// #region /api/app/proposals/sendProposals apidoc
/**
 * @api {post} /api/app/proposals/sendProposals Send Proposals
 * @apiVersion 1.0.0
 * @apiName Send Proposals
 * @apiDescription Send Proposals
 * @apiGroup Proposals - App
 * @apiParam  {Number}          proposalUserId                Requires proposalUserId of Proposals.
 * @apiParamExample {json} Request-Example:
 * {
 *      "proposalUserId": "24"
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *    {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert User Proposals",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 14,
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
router.post('/sendProposals', controller.sendProposals);

// #region /api/app/proposals/acceptRejectProposals apidoc
/**
 * @api {post} /api/app/proposals/acceptRejectProposals Accept Reject Proposals
 * @apiVersion 1.0.0
 * @apiName Accept Reject Proposals
 * @apiDescription Accept Reject Proposals
 * @apiGroup Proposals - App
 * @apiParam  {Number}          id                        Requires id of Proposals.
 * @apiParamExample {json} Request-Example:
 *  {
 *    "id": 8,
 *    "status": true
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Update User Proposals",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 0,
 *             "insertId": 0,
 *             "serverStatus": 2,
 *             "warningCount": 0,
 *             "message": "(Rows matched: 0  Changed: 0  Warnings: 0",
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
router.post('/acceptRejectProposals', controller.acceptRejectProposals);

export = router;