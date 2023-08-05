import express from 'express';
import controller from '../../controllers/admin/report';

const router = express.Router();

// #region /api/admin/report/getMasterEntryData apidoc
/**
 * @api {post} /api/admin/report/getMasterEntryData Get Master Entry Data
 * @apiVersion 1.0.0
 * @apiName Get Master Entry Data
 * @apiDescription Get Master Entry Data
 * @apiGroup Report - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *      {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Application User Report Successfully",
 *          "recordList": [
 *              {
 *                  "occupation": [{}, {}, …]
 *      	        "education": [{}, {}, …]
 *      	        "maritalStatus": [{}, {}, …]
 *      	        "religion": [{}, {}, …]
 *      	        "community": [{}, {}, …]
 *      	        "subCommunity": [{}, {}, …]
 *      	        "diet": [{}, {}, …]
 *      	        "height": [{}, {}, …]
 *      	        "annualIncome": [{}, {}, …]
 *               }
 *            ]
 *          "totalRecords": 1,
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
router.post('/getMasterEntryData', controller.getMasterEntryData);

// #region /api/admin/report/getApplicationUserReport apidoc
/**
 * @api {post} /api/admin/report/getApplicationUserReport Get Application User Report
 * @apiVersion 1.0.0
 * @apiName Get Application User Report
 * @apiDescription Get Application User Report
 * @apiGroup Report - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Application User Report Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "userId": 25,
 *                 "imageUrl": null,
 *                 "firstName": "Bhavin",
 *                 "middleName": null,
 *                 "lastName": "Panchal",
 *                 "contactNo": "3265478912",
 *                 "email": "bhavin123@gmail.com",
 *                 "gender": "Male",
 *                 "birthDate": null,
 *                 "eyeColor": "Brown",
 *                 "languages": "Hindi",
 *                 "addressLine1": "Gangadhara",
 *                 "addressLine2": "Bardoli",
 *                 "pincode": "380058",
 *                 "cityName": "Bopal",
 *                 "state": "GUJARAT",
 *                 "maritalStatus": "Married",
 *                 "religion": "Islam",
 *                 "community": "Singh",
 *                 "occupation": "Doctor",
 *                 "education": "BE",
 *                 "subCommunity": "Brahmin",
 *                 "annualIncome": "30000",
 *                 "diet": "nonveg",
 *                 "height": "100cm"
 *             },....
 *         ],
 *         "totalRecords": 5,
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
router.post('/getApplicationUserReport', controller.getApplicationUserReport);

// #region /api/admin/report/getSendProposalReqReport apidoc
/**
 * @api {post} /api/admin/report/getSendProposalReqReport Get Proposal Request Send Report
 * @apiVersion 1.0.0
 * @apiName Get Proposal Request Send Report
 * @apiDescription Get Proposal Request Send Report
 * @apiGroup Report - Admin
 * @apiParam  {Number}         year                  Requires year For Getting Report.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "year": 2022
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Send Proposal Request Report Successfully",
 *         "recordList": [
 *             {
 *                 "month": "January",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "February",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "March",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "April",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "May",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "June",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "July",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "August",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "September",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "October",
 *                 "count": 8
 *             },
 *             {
 *                 "month": "November",
 *                 "count": 4
 *             },
 *             {
 *                 "month": "December",
 *                 "count": 0
 *             }
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
router.post('/getSendProposalReqReport', controller.getSendProposalReqReport);

// #region /api/admin/report/getReceiveProposalReqReport apidoc
/**
 * @api {post} /api/admin/report/getReceiveProposalReqReport Get Proposal Request Receive Report
 * @apiVersion 1.0.0
 * @apiName Get Proposal Request Receive Report
 * @apiDescription Get Proposal Request Receive Report
 * @apiGroup Report - Admin
 * @apiParam  {Number}         year                  Requires year For Getting Report.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "year": 2022
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Receive Proposal Request Successfully",
 *         "recordList": [
 *             {
 *                 "month": "January",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "February",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "March",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "April",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "May",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "June",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "July",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "August",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "September",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "October",
 *                 "count": 5
 *             },
 *             {
 *                 "month": "November",
 *                 "count": 5
 *             },
 *             {
 *                 "month": "December",
 *                 "count": 0
 *             }
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
router.post('/getReceiveProposalReqReport', controller.getReceiveProposalReqReport);

// #region /api/admin/report/getRejectProposalReqReport apidoc
/**
 * @api {post} /api/admin/report/getRejectProposalReqReport Get Proposal Request Reject Report
 * @apiVersion 1.0.0
 * @apiName Get Proposal Request Reject Report
 * @apiDescription Get Proposal Request Reject Report
 * @apiGroup Report - Admin
 * @apiParam  {Integer}         year                  Requires year For Getting Report.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "year": 2022
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Proposal Request Reject Successfully",
 *         "recordList": [
 *             {
 *                 "month": "January",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "February",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "March",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "April",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "May",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "June",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "July",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "August",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "September",
 *                 "count": 0
 *             },
 *             {
 *                 "month": "October",
 *                 "count": 2
 *             },
 *             {
 *                 "month": "November",
 *                 "count": 1
 *             },
 *             {
 *                 "month": "December",
 *                 "count": 0
 *             }
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
router.post('/getRejectProposalReqReport', controller.getRejectProposalReqReport);

// #region /api/admin/report/getTopProposalSendReqReport apidoc
/**
 * @api {post} /api/admin/report/getTopProposalSendReqReport Get Top proposal Send Request Report
 * @apiVersion 1.0.0
 * @apiName Get Top proposal Send Request Report
 * @apiDescription Get Top proposal Send Request Report
 * @apiGroup Report - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Top proposal Send Request Report Successfully",
 *         "recordList": [
 *             {
 *                 "id": 24,
 *                 "sendRequest": 4,
 *                 "firstName": "Kinjal",
 *                 "middleName": null,
 *                 "lastName": "Patel",
 *                 "gender": "Female",
 *                 "email": "kinjal123@gmail.com",
 *                 "contactNo": "3265478912",
 *                 "imageUrl": null
 *             },....
 *         ],
 *         "totalRecords": 6,
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
router.post('/getTopProposalSendReqReport', controller.getTopProposalSendReqReport);

// #region /api/admin/report/getTopProposalReceiveReqReport apidoc
/**
 * @api {post} /api/admin/report/getTopProposalReceiveReqReport Get Top proposal Receive Request Report
 * @apiVersion 1.0.0
 * @apiName Get Top proposal Receive Request Report
 * @apiDescription Get Top proposal Receive Request Report
 * @apiGroup Report - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Top proposal Receive Request Report Successfully",
 *         "recordList": [
 *             {
 *                 "id": 22,
 *                 "receiveRequest": 4,
 *                 "firstName": "Rahul",
 *                 "middleName": null,
 *                 "lastName": "Gamit",
 *                 "gender": "Male",
 *                 "email": "rahul123@gmail.com",
 *                 "contactNo": "3265478912",
 *                 "imageUrl": "content/user/22/26.jpeg"
 *             },.....
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
router.post('/getTopProposalReceiveReqReport', controller.getTopProposalReceiveReqReport);

// #region /api/admin/report/getMonthlySendProposalUser apidoc
/**
 * @api {post} /api/admin/report/getMonthlySendProposalUser Get Monthly Send Proposal User Report
 * @apiVersion 1.0.0
 * @apiName Get Monthly Send Proposal User Report
 * @apiDescription Get Monthly Send Proposal User Report
 * @apiGroup Report - Admin
 * @apiParam  {Number}         year                  Requires year For Getting Report.
 * @apiParam  {String}         Month                 Requires Month For Getting Report.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "year": 2022
 *         "month": "October"
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
{
    "status": 200,
    "isDisplayMessage": true,
    "message": "Get Month Wise Send Proposal Users Successfully",
    "recordList": [
        {
            "id": 22,
            "proposalUserId": 25,
            "userName": "Rahul Gamit",
            "proposalName": "Bhavin Panchal",
            "createdDate": "2022-10-17T09:32:14.000Z",
            "month": "October"
        },.....
    ],
    "totalRecords": 8,
    "token": ""
}
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
router.post('/getMonthlySendProposalUser', controller.getMonthlySendProposalUser);

// #region /api/admin/report/getMonthlyReceiveProposalUser apidoc
/**
 * @api {post} /api/admin/report/getMonthlyReceiveProposalUser Get Monthly Receive Proposal User Report
 * @apiVersion 1.0.0
 * @apiName Get Monthly Receive Proposal User Report
 * @apiDescription Get Monthly Receive Proposal User Report
 * @apiGroup Report - Admin
 * @apiParam  {Number}         year                  Requires year For Getting Report.
 * @apiParam  {String}         Month                 Requires Month For Getting Report.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "year": 2022
 *         "month": "October"
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Monthly Receive Proposal Users Successfully",
 *         "recordList": [
 *             {
 *                 "id": 22,
 *                 "proposalUserId": 25,
 *                 "userName": "Rahul Gamit",
 *                 "proposalName": "Bhavin Panchal",
 *                 "createdDate": "2022-10-17T09:32:14.000Z",
 *                 "month": "October"
 *             },...
 *                 ],
 *         "totalRecords": 5,
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
router.post('/getMonthlyReceiveProposalUser', controller.getMonthlyReceiveProposalUser);

// #region /api/admin/report/getMonthlyRejectProposalUser apidoc
/**
 * @api {post} /api/admin/report/getMonthlyRejectProposalUser Get Monthly Reject Proposal User Report
 * @apiVersion 1.0.0
 * @apiName Get Monthly Reject Proposal User Report
 * @apiDescription Get Monthly Reject Proposal User Report
 * @apiGroup Report - Admin
 * @apiParam  {Number}         year                  Requires year For Getting Report.
 * @apiParam  {String}         Month                 Requires Month For Getting Report.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "year": 2022
 *         "month": "November"
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Monthly Rejected Proposal Users Successfully",
 *         "recordList": [
 *             {
 *                 "id": 56,
 *                 "proposalUserId": 24,
 *                 "userName": "Sarita Tripathi",
 *                 "proposalName": "Kinjal Patel",
 *                 "createdDate": "2022-11-10T06:40:11.000Z",
 *                 "month": "November"
 *             },.....
 *         ],
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
router.post('/getMonthlyRejectProposalUser', controller.getMonthlyRejectProposalUser);

router.post('/getPremiumAppUser', controller.getPremiumAppUser);

router.post('/getSystemBlockedUsers', controller.getSystemBlockedUsers);

export = router;