import express from 'express';
import controller from '../../controllers/admin/users';

const router = express.Router();

// #region /api/admin/users/insertUser apidoc
/**
 * @api {post} /api/admin/users/insertUser Insert User
 * @apiVersion 1.0.0
 * @apiName Insert User
 * @apiDescription Insert User
 * @apiGroup Users - Admin
 * @apiParam  {String}          firstName                   Requires Users firstName.
 * @apiParam  {String}          lasttName                   Requires Users lastName.
 * @apiParam  {String}          email                       Requires User Email.
 * @apiParam  {String}          password                    Requires hsah Password.
 * @apiParam  {String}          contactNo                   Requires user contactNo.
 * @apiParam  {String}          gender                      Requires user gender.
 * @apiParamExample {json} Request-Example:
 *     {
 *        "firstName": "Yamini",
 *        "lastName": "Patel",
 *        "email": "yamini123@gmail.com",
 *        "password": "yamini123",
 *        "contactNo": "9898989898",
 *        "gender": "female",
 *        "image":"base64 String"
 *    	}
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Insert User",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 29,
 *             "serverStatus": 3,
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
router.post('/insertUser', controller.insertUser);

// #region /api/admin/users/login apidoc
/**
 * @api {post} /api/admin/users/login Admin login
 * @apiVersion 1.0.0
 * @apiName Admin login
 * @apiDescription Admin login
 * @apiGroup Users - Admin
 * @apiParam  {String}          email                       Requires User Email.
 * @apiParam  {String}          password                    Requires hsah Password.
 * @apiParamExample {json} Request-Example:
 *     {
 *      		 "email": "heli171998@gmail.com",
 *      		 "password": "heli1234"
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *       {
 *           "status": 200,
 *           "isDisplayMessage": true,
 *           "message": "Login User",
 *           "recordList": [
 *               {
 *                   "id": 5,
 *                   "firstName": "Heli",
 *                   "middleName": "dhruvkumar",
 *                   "lastName": "Patel",
 *                   "contactNo": "5452664546",
 *                   "email": "heli171998@gmail.com",
 *                   "gender": "Female",
 *                   "password": "$2a$10$E4SVn1N8/Qy07hpX0runWeZsZB7ZbZvx7Vvm5qVKEsRa5KPtTv8T6",
 *                   "imageId": 17,
 *                   "isPasswordSet": null,
 *                   "isDisable": 0,
 *                   "isVerified": null,
 *                   "isActive": 1,
 *                   "isDelete": 0,
 *                   "createdDate": "2022-10-11T12:35:46.000Z",
 *                   "modifiedDate": "2022-10-11T12:35:46.000Z",
 *                   "roleId": 1,
 *                   "image": "content/user/5/17.jpeg",
 *                   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9. *       eyJ1c2VySWQiOjUsImlhdCI6MTY2ODQwNjk4OSwiZXhwIjoxNjY4NDEwNTg5LCJpc3MiOiJjb29sSXNzdWVyIn0. *       dhKxFjqzOZy2ayyoRP7_n2qT9rQxeJU9Y7AkbWQHA5Q",
 *                   "refreshToken": "91ce40f5-a773-4068-9291-220cbb3f46f1"
 *               }
 *           ],
 *           "totalRecords": 1,
 *           "token": ""
 *       }
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
router.post('/login', controller.login);

// #region /api/admin/users/getAllUsers apidoc
/**
 * @api {post} /api/admin/users/getAllUsers Get All Users
 * @apiVersion 1.0.0
 * @apiName Get All Users
 * @apiDescription Get All Users
 * @apiGroup Users - Admin
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Users Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "firstName": "Ankita",
 *                 "middleName": "Sanjay",
 *                 "lastName": "Tripathi",
 *                 "contactNo": "9662737261",
 *                 "email": "ankita@gmail.com",
 *                 "gender": "Female",
 *                 "password": "$2a$10$jJ3Yw5x6VGheDZE5lr.MkeedMuYvm/kcHoa8YVbY0KwfYv.L45/o6",
 *                 "imageId": null,
 *                 "isPasswordSet": 1,
 *                 "isDisable": 1,
 *                 "isVerified": 1,
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-10T04:37:44.000Z",
 *                 "modifiedDate": "2022-10-10T04:37:44.000Z",
 *                 "image": null,
 *                 "roleId": 1
 *             },.....
 *         ],
 *         "totalRecords": 8,
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
router.post('/getAllUsers', controller.getAllUsers);

// #region /api/admin/users/getUserDetailById apidoc
/**
 * @api {post} /api/admin/users/getUserDetailById Get User Detail By Id
 * @apiVersion 1.0.0
 * @apiName Get User Detail By Id
 * @apiDescription Get User Detail By Id
 * @apiGroup Users - Admin
 * @apiparam    {Number0}               id                  Requires id of Users
 * @apiParamExample {json} Request-Example:
 *     {
 *       "id": 1
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get User Detail Successfully",
 *         "recordList": [
 *             {
 *                 "id": 1,
 *                 "firstName": "Ankita",
 *                 "middleName": "Sanjay",
 *                 "lastName": "Tripathi",
 *                 "contactNo": "9662737261",
 *                 "email": "ankita@gmail.com",
 *                 "gender": "Female",
 *                 "password": "$2a$10$jJ3Yw5x6VGheDZE5lr.MkeedMuYvm/kcHoa8YVbY0KwfYv.L45/o6",
 *                 "imageId": null,
 *                 "isPasswordSet": 1,
 *                 "isDisable": 1,
 *                 "isVerified": 1,
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-10T04:37:44.000Z",
 *                 "modifiedDate": "2022-10-10T04:37:44.000Z",
 *                 "image": null,
 *                 "roleId": 1
 *             }
 *         ],
 *         "totalRecords": 8,
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
router.post('/getUserDetailById', controller.getUserDetailById);

// #region /api/admin/users/updateUser apidoc
/**
 * @api {post} /api/admin/users/updateUser Update Users
 * @apiVersion 1.0.0
 * @apiName Update Users
 * @apiDescription Update Users
 * @apiGroup Users - Admin
 * @apiParam       {Number}                 id                  Requires users id.
 * @apiParam       {Number}                 firstName           Requires users id.
 * @apiParam       {Number}                 lastName            Requires users id.
 * @apiParam       {Number}                 email               Requires users id.
 * @apiParam       {Number}                 contactNo           Requires users id.
 * @apiParam       {Number}                 gender              Requires users id.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "id": 40,
 *         "firstName": "Adarsh",
 *         "lastName": "Tripathi",
 *         "email": "adarsh123@gmail.com",
 *         "contactNo": "9898989898",
 *         "gender": "male",
 *         "image": "base64 String"
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Update User Detail",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 0,
 *             "serverStatus": 3,
 *             "warningCount": 0,
 *             "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
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
router.post('/updateUser', controller.updateUser);

// #region /api/admin/users/validateToken apidoc
/**
 * @api {post} /api/admin/users/validateToken Admin validateToken
 * @apiVersion 1.0.0
 * @apiName Admin validateToken
 * @apiDescription Admin validateToken
 * @apiGroup validateToken - Admin
 * @apiParam  {String}          token                       Requires Token.
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          status: 200,
 *          isDisplayMessage: <true/false>, // if the value is true then display message on screen
 *          message: 'Insert User',
 *          recordList: Users,
 *          totalRecords: TotalRecords
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
router.post('/validateToken', controller.validateToken);

// #region /api/admin/users/resetPassword apidoc
/**
 * @api {post} /api/admin/users/resetPassword Reset Password
 * @apiVersion 1.0.0
 * @apiName Reset Password
 * @apiDescription Reset Password
 * @apiGroup Users - Admin
 * @apiParamExample {json} Request-Example:
 *    {
 *        "userId": 1,
 *        "password": "ankita123",
 *        "token": "0257d030db7b3c90471310136fe9873fe00be074257a2e4f5451c2aee4c1ea1c707e3c6f520e127d969356d61b6a5fe4"
 *    }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Password reset successfully!",
 *         "recordList": {
 *             "fieldCount": 0,
 *             "affectedRows": 1,
 *             "insertId": 0,
 *             "serverStatus": 2,
 *             "warningCount": 0,
 *             "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
 *             "protocol41": true,
 *             "changedRows": 1
 *         },
 *         "totalRecords": 1,
 *         "token": "null"
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
router.post('/resetPassword', controller.resetPassword);

// #region /api/admin/users/forgotPassword apidoc
/**
 * @api {post} /api/admin/users/forgotPassword Forgot Password
 * @apiVersion 1.0.0
 * @apiName Forgot Password
 * @apiDescription Forgot Password
 * @apiGroup Users - Admin
 * @apiParam  {string}          email                     Requires email of users.
 * @apiParamExample {json} Request-Example:
 *      {
 *          "email": "ankitatripathioo932@gmail.com"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Send mail successfully!",
 *         "recordList": {
 *             "accepted": [
 *                 "ankitatripathioo932@gmail.com"
 *             ],
 *             "rejected": [],
 *             "envelopeTime": 838,
 *             "messageTime": 733,
 *             "messageSize": 752,
 *             "response": "250 2.0.0 OK  1667197266 i2-20020a170902cf0200b0016dbdf7b97bsm3624747plg.266 - gsmtp",
 *             "envelope": {
 *                 "from": "1998shahnishi@gmail.com",
 *                 "to": [
 *                     "ankitatripathioo932@gmail.com"
 *                 ]
 *             },
 *             "messageId": "<790716ac-62df-9ffe-517c-00c33ddd934c@gmail.com>"
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
router.post('/forgotPassword', controller.forgotPassword);

// #region /api/admin/users/verifyforgotPasswordLink apidoc
/**
 * @api {post} /api/admin/users/verifyforgotPasswordLink Verify Forgort Password Link
 * @apiVersion 1.0.0
 * @apiName Verify Forgort Password Link
 * @apiDescription Verify Forgort Password Link
 * @apiGroup Users - Admin
 * @apiParam    {String}           Token                Requires Link Token
 * @apiParamExample {json} Request-Example:
 *    {
 *   "token": "0257d030db7b3c90471310136fe9873fe00be074257a2e4f5451c2aee4c1ea1c707e3c6f520e127d969356d61b6a5fe4"
 *    }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Password reset successfully!",
 *         "recordList": [
 *             {
 *                 "id": 8,
 *                 "userId": 1,
 *                 "token": "0257d030db7b3c90471310136fe9873fe00be074257a2e4f5451c2aee4c1ea1c707e3c6f520e127d969356d61b6a5fe4",
 *                 "isUsed": 0,
 *                 "expireAt": "2022-11-01T06:29:42.000Z",
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-31T06:29:42.000Z",
 *                 "modifiedDate": "2022-10-31T06:29:42.000Z",
 *                 "createdBy": null,
 *                 "modifiedBy": null
 *             }
 *         ],
 *         "totalRecords": 1,
 *         "token": "null"
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
router.post('/verifyforgotPasswordLink', controller.verifyforgotPasswordLink);

// #region /api/admin/users/activeInactiveUsers apidoc
/**
 * @api {post} /api/admin/users/activeInactiveUsers Change User 
 * @apiVersion 1.0.0
 * @apiName Change Users Status
 * @apiDescription Change Users Status
 * @apiGroup Users - Admin
 * @apiParam  {Integer}         id                  Requires Users Id.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "id": 24
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Change Users Status",
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
router.post('/activeInactiveUsers', controller.activeInactiveUsers);

// #region /api/admin/users/blockUser apidoc
/**
 * @api {post} /api/admin/users/blockUser Block User
 * @apiVersion 1.0.0
 * @apiName Block User
 * @apiDescription Block Users
 * @apiGroup Users - Admin
 * @apiParam  {Integer}         id                  Requires Users id.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "id": 1,
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "User Block Sucessfully",
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
router.post('/blockUser', controller.blockUser);

// #region /api/admin/users/deleteUser apidoc
/**
 * @api {post} /api/admin/users/deleteUser Delete User
 * @apiVersion 1.0.0
 * @apiName Delete User
 * @apiDescription Delete Users
 * @apiGroup Users - Admin
 * @apiParam  {Integer}         id                  Requires Users id.
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          status: 200,
 *          isDisplayMessage: <true/false>, // if the value is true then display message on screen
 *          message: 'Delete Users',
 *          recordList: Users,
 *          totalRecords: TotalRecords
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
router.post('/deleteUser', controller.deleteUser);

export = router;