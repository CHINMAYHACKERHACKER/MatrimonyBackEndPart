import express from 'express';
import controller from '../../controllers/app/successStories';

const router = express.Router();

// #region /api/app/successStories/getPartnerList apidoc
/**
 * @api {post} /api/app/successStories/getPartnerList Get Partner List
 * @apiVersion 1.0.0
 * @apiName Get Partner List
 * @apiDescription Get Partner List
 * @apiGroup Success Stories - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Partner List Successfully",
 *          "recordList": [
 *              {
 *                  "id": 1
 *                  "userId": 78,
 *                  "partnerUserId": 23,
 *                  "imageId": null,
 *                  "maritalStatus": "Married",
 *                  "isActive": 1,
 *                  "isDelete": 0,
 *                  "createdDate": "2022-10-18T10:24:55.000Z"
 *                  "modifiedDate": "2022-10-18T10:24:55.000Z",
 *                  "createdBy": 78,
 *                  "modifiedBy": 78,
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
router.post('/getPartnerList', controller.getPartnerList);

// #region /api/app/successStories/getSuccessStories apidoc
/**
 * @api {post} /api/app/successStories/getSuccessStories Get Success Stories
 * @apiVersion 1.0.0
 * @apiName Get Success Stories
 * @apiDescription Get Success Stories
 * @apiGroup Success Stories - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get Success Stories Successfully",
 *          "recordList": [
 *              {
 *                  "id": 1
 *                  "userId": 22,
 *                  "partnerUserId": 23,
 *                  "imageId": null,
 *                  "maritalStatus": married,
 *                  "isActive": "1",
 *                  "isDelete": "0",
 *                  "createdDate": "2022-10-19 10:49:52",
 *                  "modifiedDate": "2022-10-19 10:49:52",
 *                  "createdBy": "22",
 *                  "modifiedBy": "22",
 *                  "imageUrl": null
 *                  "userFName": "Ankita",
 *                  "userLName": "Tripathi",
 *                  "userGender": "Female",
 *                  "userEmail": ankita@gmail.com,
 *                  "userImage": "null",
 *                  "userCity": "Surat",
 *                  "partnerFName": "Vivek",
 *                  "partnerLName": "Mishra",
 *                  "partnerGender": "Male",
 *                  "partnerEmail": "vivek@gamil.com",
 *                  "partnerImage": null,
 *                  "partnerCity": "Jaipur"
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
router.post('/getSuccessStories', controller.getSuccessStories);

// #region /api/app/successStories/insertSuccessStories apidoc
/**
 * @api {post} /api/app/successStories/insertSuccessStories Insert Success Stories
 * @apiVersion 1.0.0
 * @apiName Insert Success Stories
 * @apiDescription Insert Success Stories
 * @apiGroup Success Stories - App
 * @apiParam  {Number}          userID                       Requires userID of Success Stories.
 * @apiParam  {Number}          partnerUserId                Requires partnerUserId of Success Stories.
 * @apiParam  {Number}          image                        Requires image of Success Stories in base 64.
 * @apiParamExample {json} Request-Example:
 * {
 *      "userId": "24",
 *      "partnerUserId": "26",
 *      "image": "gdfghfhbgnvhg" (base 64 string)
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *    {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert Success Stories Successfully",
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
router.post('/insertSuccessStories', controller.insertSuccessStories);

export = router;
