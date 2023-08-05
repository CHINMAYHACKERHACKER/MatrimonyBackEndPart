import express from 'express';
import controller from '../../controllers/app/feedback';

const router = express.Router();

// #region /api/app/feedback/insertFeedback apidoc
/**
 * @api {post} /api/app/feedback/insertFeedback Insert User Feedback
 * @apiVersion 1.0.0
 * @apiName Insert User Feedback
 * @apiDescription Insert User Feedback
 * @apiGroup User Feedback - App
 * @apiParam  {Number}          blockRequestUserId         Requires blockRequestUserId of UserBlockRequest.
 * @apiParamExample {json} Request-Example:
{
    "userId":74,
    "description":"this is testing",
    "title" : "title"
}
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 {
    "status": 200,
    "isDisplayMessage": true,
    "message": "Insert User FeedBack",
    "recordList": {
        "fieldCount": 0,
        "affectedRows": 1,
        "insertId": 1,
        "serverStatus": 2,
        "warningCount": 0,
        "message": "",
        "protocol41": true,
        "changedRows": 0
    },
    "totalRecords": 1,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjc0LCJpYXQiOjE2Nzk1NzAwNTcsImV4cCI6MTY3OTU3MDM1NywiaXNzIjoiY29vbElzc3VlciJ9.O5Cnlz4OuTZtQ9STUutNRa_nK-V-oDmMxNhB3L70UPw"
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

router.post('/insertFeedback', controller.insertFeedback);
// #region /api/app/feedback/getFeedback apidoc
/**
 * @api {post} /api/app/feedback/getFeedback Get User Feedback
 * @apiVersion 1.0.0
 * @apiName Get User Feedback
 * @apiDescription Get User Feedback
 * @apiGroup User Feedback - Admin
 * @apiParam  {Number}          blockRequestUserId         Requires blockRequestUserId of UserBlockRequest.

 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
{
    "status": 200,
    "isDisplayMessage": true,
    "message": "Get Feedback Successfully",
    "recordList": [
        {
            "id": 1,
            "userId": 74,
            "description": "this is testing",
            "title": "title",
            "transactionDate": "2023-03-23T11:14:48.000Z",
            "isActive": 1,
            "isDelete": 0,
            "createdDate": "2023-03-23T11:14:48.000Z",
            "modifiedDate": "2023-03-23T11:14:48.000Z",
            "createdBy": 74,
            "modifiedBy": 74
        }
    ],
    "totalRecords": 1,
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjc0LCJpYXQiOjE2Nzk1NzE0ODksImV4cCI6MTY3OTU3MTc4OSwiaXNzIjoiY29vbElzc3VlciJ9.gnsOapvGnWmwvp8BbiC4sHpl-BhbJCRMxWSMZtydf7I"
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

// router.post('/getFeedback', controller.getFeedback);

export = router;