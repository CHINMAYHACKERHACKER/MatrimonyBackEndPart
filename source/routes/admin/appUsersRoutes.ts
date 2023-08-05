import express from 'express';
import controller from '../../controllers/admin/appUsers';

const router = express.Router();

// #region /api/admin/appUsers/getAppUsers apidoc
/**
 * @api {post} /api/admin/appUsers/getAppUsers Get App Users
 * @apiVersion 1.0.0
 * @apiName Get App Users
 * @apiDescription Get App Users
 * @apiGroup App Users - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *      {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Get App Users Successfully",
 *          "recordList": [
 *              {
 *                  "id": 21,
 *                  "firstName": "Yogita",
 *                  "middleName": null,
 *                  "lastName": "patel",
 *                  "contactNo": "3698521473",
 *                  "email": "yogita123@gmail.com",
 *                  "gender": "Female",
 *                  "password": "$2a$10$nw1VRpDUxFCSUybngKyM9.9WlnkZqapcfa1gAJjYLq4KIB1TFral.",
 *                  "imageId": null,
 *                  "isPasswordSet": null,
 *                  "isDisable": 0,
 *                  "isVerified": null,
 *                  "isActive": 1,
 *                  "isDelete": 0,
 *                  "createdDate": "2022-10-17T09:13:57.000Z",
 *                  "modifiedDate": "2022-10-17T09:13:57.000Z",
 *                  "roleId": 2
 *              },...
 *          ],
 *          "totalRecords": 8,
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
router.post('/getAppUsers', controller.getAppUsers);

// #region /api/admin/appUsers/viewAppUserPerDetail apidoc
/**
 * @api {post} /api/admin/appUsers/viewAppUserPerDetail View App User Detail
 * @apiVersion 1.0.0
 * @apiName View App Users Detail
 * @apiDescription View App Users Detail
 * @apiGroup App Users - Admin
 * @apiParam  {Number}          userId                        Requires userId of App USers.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "userId": 22
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get App User Detail Successfully",
 *         "recordList": [
 *             {
 *                 "id": 22,
 *                 "firstName": "Rahul",
 *                 "middleName": null,
 *                 "lastName": "Gamit",
 *                 "gender": "Male",
 *                 "email": "rahul123@gmail.com",
 *                 "contactNo": "3265478912",
 *                 "birthDate": "1995-09-23T18:30:00.000Z",
 *                 "languages": "Gujarati",
 *                 "eyeColor": "Black",
 *                 "imageUrl": "content/user/22/26.jpeg",
 *                 "religion": "Sikh",
 *                 "maritalStatus": "Married",
 *                 "community": "Trivedi",
 *                 "occupation": "Designer",
 *                 "education": "B pharm",
 *                 "subCommunity": "Brahmin",
 *                 "annualIncome": "4 lakh",
 *                 "diet": "Jain",
 *                 "height": "130 cm",
 *                 "addressLine1": "Gangadhara",
 *                 "addressLine2": "Bardoli",
 *                 "pincode": "380058",
 *                 "cityName": "Bopal",
 *                 "state": "GUJARAT",
 *                 "country": "India"
 *             }
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
router.post('/viewAppUserPerDetail', controller.viewAppUserPerDetail);

// #region /api/admin/appUsers/viewAppUserSendRequest apidoc
/**
 * @api {post} /api/admin/appUsers/viewAppUserSendRequest View App User Send Request
 * @apiVersion 1.0.0
 * @apiName View App Users Send Request
 * @apiDescription View App Users Send Request
 * @apiGroup App Users - Admin
 * @apiParam  {Number}          userId                        Requires userId of App USers.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "userId": 22,
 *       "startIndex": 0,
 *       "fetchRecord": 1
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get App User Detail Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "userId": 22,
 *                 "proposalUserId": 25,
 *                 "status": 1,
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-17T10:37:07.000Z",
 *                 "modifiedDate": "2022-10-17T10:37:07.000Z",
 *                 "createdBy": 22,
 *                 "modifiedBy": 22,
 *                 "firstName": "Bhavin",
 *                 "lastName": "Panchal",
 *                 "gender": "Male",
 *                 "email": "bhavin123@gmail.com",
 *                 "contactNo": "3265478912",
 *                 "imageUrl": null
 *             }
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
router.post('/viewAppUserSendRequest', controller.viewAppUserSendRequest);

// #region /api/admin/appUsers/viewAppUserGotRequest apidoc
/**
 * @api {post} /api/admin/appUsers/viewAppUserGotRequest View App User Got Request
 * @apiVersion 1.0.0
 * @apiName View App Users Got Request
 * @apiDescription View App Users Got Request
 * @apiGroup App Users - Admin
 * @apiParam  {Number}          userId                        Requires userId of App USers.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "userId": 22,
 *       "startIndex": 0,
 *       "fetchRecord": 1
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get App User Detail Successfully",
 *         "recordList": [
 *             {
 *                 "id": 7,
 *                 "userId": 24,
 *                 "proposalUserId": 22,
 *                 "status": 1,
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-18T10:25:55.000Z",
 *                 "modifiedDate": "2022-10-18T10:25:55.000Z",
 *                 "createdBy": 25,
 *                 "modifiedBy": 25,
 *                 "firstName": "Kinjal",
 *                 "lastName": "Patel",
 *                 "gender": "Female",
 *                 "email": "kinjal123@gmail.com",
 *                 "contactNo": "3265478912",
 *                 "imageUrl": null
 *             }
 *         ],
 *         "totalRecords": 4,
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
router.post('/viewAppUserGotRequest', controller.viewAppUserGotRequest);

// #region /api/admin/appUsers/viewAppUserFavourites apidoc
/**
 * @api {post} /api/admin/appUsers/viewAppUserFavourites View App User Favourites
 * @apiVersion 1.0.0
 * @apiName View App Users Favourites
 * @apiDescription View App Users Favourites
 * @apiGroup App Users - Admin
 * @apiParam  {Number}          userId                        Requires userId of App USers.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "userId": 22,
 *       "startIndex": 0,
 *       "fetchRecord": 1
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get App User Detail Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "userId": 22,
 *                 "favUserId": 25,
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-19T05:19:52.000Z",
 *                 "modifiedDate": "2022-10-19T05:19:52.000Z",
 *                 "createdBy": 25,
 *                 "modifiedBy": 25,
 *                 "firstName": "Bhavin",
 *                 "lastName": "Panchal",
 *                 "gender": "Male",
 *                 "email": "bhavin123@gmail.com",
 *                 "contactNo": "3265478912",
 *                 "imageUrl": null
 *             }
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
router.post('/viewAppUserFavourites', controller.viewAppUserFavourites);

router.post('/viewBlockUser',controller.viewBlockUser)

router.post('/unblockUserRequest',controller.unblockUserRequest)

export = router;