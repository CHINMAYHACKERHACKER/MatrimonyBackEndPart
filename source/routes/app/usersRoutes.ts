import express from 'express';
import controller from '../../controllers/app/users';

const router = express.Router();

// #region /api/app/users/verifyEmailContact apidoc
/**
 * @api {post} /api/app/users/verifyEmailContact Verify Email Contact
 * @apiVersion 1.0.0
 * @apiName Verify Email Contact
 * @apiDescription Verify Email Contact
 * @apiGroup Users - App
 * @apiParam {string}                email                       Require email of users.
 * @apiParam {string}                contactNo                   Require contactNo of users.
 * @apiParamExample {json} Request-Example:
 *  {
 *       "email": "EmailId",
 *       "contactNo": "ContactNo"
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Email Already Exist!",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
 *              "protocol41": true,
 *              "changedRows": 1
 *          },
 *          "totalRecords": 1,
 *          "token": "null"
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
router.post('/verifyEmailContact', controller.verifyEmailContact);

// #region /api/app/users/signUp apidoc
/**
 * @api {post} /api/app/users/signUp App signUp
 * @apiVersion 1.0.0
 * @apiName App signUp
 * @apiDescription App signUp
 * @apiGroup Users - App
 * @apiParam  {String}          conṭactNo                   Requires Users conṭactNo.
 * @apiParam  {String}          email                       Requires User Email.
 * @apiParam  {String}          password                    Requires hsah Password.
 * @apiParamExample {json} Request-Example:
 * {
 *   "email": "dipa123@gmail.com",
 *   "contactNo": "3265478912",
 *   "password": "dipa123",
 * }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample  {json} Success-Response:
 * HTTP/1.1 200 OK:
 *  {
 *      "status": 200,
 *      "isDisplayMessage": true,
 *      "message": "Login User",
 *      "recordList": [
 *        {
 *            "id": 6,
 *            "firstName": "Prabhuti",
 *            "middleName": null,
 *            "lastName": "Patel",
 *            "contactNo": "3698524789",
 *            "email": "prabhuti@gmail.com",
 *            "gender": "Female",
 *            "password": "$2a$10$iBa/dK5lDZtNF5kkjrWXquVfllsq2zKxrVJDam0xf28rWO0ZnsMcG",
 *            "imageId": null,
 *            "isPasswordSet": null,
 *            "isDisable": null,
 *            "isVerified": null,
 *            "isActive": 1,
 *            "isDelete": 0,
 *            "createdDate": "2022-10-11T12:37:53.000Z",
 *            "modifiedDate": "2022-10-11T12:37:53.000Z",
 *            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.*eyJ1c2VySWQiOjYsImlhdCI6MTY2NjQxNjI4NSwiZXhwIjoxNjY2NDE5ODg1LCJpc3MiOiJjb29sSXNzdWVyIn0.*5FsXF0mXLBt5hSgMe5K8Bj3zb6kgWHV5Cx4hhCokhoo",
 *           "refreshToken": "19a3e8cf-7203-4154-b409-e100eff229f7"
 *       }
 *   ],
 *      "totalRecords": 1,
 *      "token": ""
 *   }
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
router.post('/signUp', controller.signUp);

// #region /api/app/users/login apidoc
/**
 * @api {post} /api/app/users/login App login
 * @apiVersion 1.0.0
 * @apiName App login
 * @apiDescription App login
 * @apiGroup Users - App
 * @apiParam  {String}          email                       Requires User Email.
 * @apiParam  {String}          password                    Requires hsah Password.
 * @apiParamExample {json} Request-Example:
 *  {
 *      "email": "dipa123@gmail.com",
 *      "password": "dip123",
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *    {
 *       "status": 200,
 *        "isDisplayMessage": true,
 *        "message": "Login User",
 *        "recordList": [
 *            {
 *                "id": 52,
 *                "firstName": null,
 *                "middleName": null,
 *                "lastName": null,
 *                "contactNo": "3265478912",
 *                "email": "dipa123@gmail.com",
 *                "gender": null,
 *                "password": "$2a$10$RNcv/Gtfo.xrCeufNFGiweWdCIe/n7asO.2FJqL3FYrWxgPmhRa2m",
 *                "imageId": null,
 *                "isPasswordSet": null,
 *                "isDisable": null,
 *                "isVerified": null,
 *                "isActive": 1,
 *                "isDelete": 0,
 *                "createdDate": "2022-11-02T09:00:52.000Z",
 *                "modifiedDate": "2022-11-02T09:00:52.000Z",
 *                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9. *    eyJ1c2VySWQiOjUyLCJpYXQiOjE2NjczNzk5NDQsImV4cCI6MTY2NzM4MzU0NCwiaXNzIjoiY29vbElzc3VlciJ9. *    MM-3xXqNcfNRUBVcML9Y09Sf82sN8bCj4BTgKOO6IBk",
 *                "refreshToken": "b7f3717d-8601-4fff-95d8-c3ab52cc5acb"
 *            }
 *        ],
 *        "totalRecords": 1,
 *        "token": ""
 *        "masterEntryData": {
 *        "occupation": occupationResult,
 *        "education": educationResult,
 *        "maritalStatus": maritalStatusResult,
 *        "religion": religionResult,
 *        "community": communityResult,
 *        "subCommunity": subCommunityResult,
 *        "diet": dietResult,
 *        "height": heightResult,
 *        "annualIncome": annualIncomeResult
 *        }
 *    }
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

// #region /api/app/users/getMasterData apidoc
/**
 * @api {post} /api/app/users/getMasterData Get Master Data
 * @apiVersion 1.0.0
 * @apiName Get Master Data
 * @apiDescription Get Master Data
 * 
 * @apiGroup Users - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Master Data Successfully",
 *         "recordList": {
 *            "occupation": [
 *                 {
 *                     "id": 1,
 *                     "parentId": null,
 *                     "name": "Teacher",
 *                     "isActive": 1,
 *                     "isDelete": 0,
 *                     "createdDate": "2022-10-13T11:02:56.000Z",
 *                     "modifiedDate": "2022-10-13T11:02:56.000Z",
 *                     "createdBy": 6,
 *                     "modifiedBy": 6
 *                 },
 *              ],
 *                "education": [],
 *                "maritalStatus":[],
 *                "religion": [],
 *                "community": [],
 *                "subCommunity": [],
 *                "diet": [],
 *                "height": [],
 *                "annualIncome": []
 *         },
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
router.post('/getMasterData', controller.getMasterData);

// #region /api/app/users/getAllUsers apidoc
/**
 * @api {post} /api/app/users/getAllUsers Get All Users
 * @apiVersion 1.0.0
 * @apiName Get All Users
 * @apiDescription Get All Users
 * @apiGroup Users - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *    {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Users Successfully",
 *         "recordList": [
 *             {
 *                 "id": 21,
 *                 "firstName": "Yogita",
 *                 "middleName": null,
 *                 "lastName": "patel",
 *                 "contactNo": "3698521473",
 *                 "email": "yogita123@gmail.com",
 *                 "gender": "Female",
 *                 "password": "$2a$10$nw1VRpDUxFCSUybngKyM9.9WlnkZqapcfa1gAJjYLq4KIB1TFral.",
 *                 "imageId": null,
 *                 "isPasswordSet": null,
 *                 "isDisable": null,
 *                 "isVerified": null,
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-10-17T09:13:57.000Z",
 *                 "modifiedDate": "2022-10-17T09:13:57.000Z",
 *                 "image": null
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
router.post('/getAllUsers', controller.getAllUsers);

// #region /api/app/users/viewUserDetail apidoc
/**
 * @api {post} /api/app/users/viewUserDetail View User Detail
 * @apiVersion 1.0.0
 * @apiName View User Detail
 * @apiDescription View User Detail
 * @apiGroup Users - App
 * @apiParam  {number}          id                    Requires users id.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "id": 22
 *     }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Users Detail Successfully",
 *         "recordList": [
 *             {
 *                 "id": 22,
 *                 "imageUrl": null,
 *                 "firstName": "Rahul",
 *                 "middleName": null,
 *                 "lastName": "Gamit",
 *                 "contactNo": "3265478912",
 *                 "email": "rahul123@gmail.com",
 *                 "gender": "Male",
 *                 "birthDate": null,
 *                 "eyeColor": "Black",
 *                 "languages": "Gujarati",
 *                 "addressLine1": "Gangadhara",
 *                 "addressLine2": "Bardoli",
 *                 "pincode": "380058",
 *                 "cityName": "Bopal",
 *                 "state": "GUJARAT",
 *                 "maritalStatus": "Married",
 *                 "religion": "Sikh",
 *                 "community": "Trivedi",
 *                 "occupation": "Designer",
 *                 "education": "Bpharm",
 *                 "subCommunity": "Brahmin",
 *                 "annualIncome": "4 Lakh",
 *                 "diet": "jain",
 *                 "height": "100cm",
 *                 "age": "25"
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
router.post('/viewUserDetail', controller.viewUserDetail);

// #region /api/app/users/updateUserProfilePic apidoc
/**
 * @api {post} /api/app/users/updateUserProfilePic Update Users Profile Pic
 * @apiVersion 1.0.0
 * @apiName Update Users Profile Pic
 * @apiDescription Update Users Profile Pic
 * @apiGroup Users - App
 * @apiParam  {string}          image                          Requires User image (base 64).
 * @apiParamExample {json} Request-Example:
 *   {
 *     "id": "52",
 *     "image":"data:image/jpeg;base64,/9j/4AAQSkZJRgABAgEBLAEsAAD/4QDgRXhpZgAATU0AKgAAAAgACQEAAAQAAAABAAASQwEBAAQAAAABAAASQwESAAMAAAABAAEAAAEaAAUAAAABAAAAegEbAAUAAAABAAAAggExAAIAAAAOAAAAigEyAAIAAAAUAAAAmIKYAAIAAAAOAAAArIdpAAQAAAABAAAAugAAAAAAAAEsAAAAAQAAASwAAAABcmF3cGl4ZWwgbHRkLgAyMDE3OjEwOjA5IDA5OjMxOjA5AFJhd3BpeGVsIEx0ZC4AAAKQAAAHAAAABDAyMjGgAQADAAAAAf//AAAAAAAA/+GWuGh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8APD94cGFja2V0IGJlZ2luPSfvu78nIGlkPSdXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQnPz4KPHg6eG1wbWV0YSB4bWxuczp4PSdhZG9iZTpuczptZXRhLycgeDp4bXB0az0nSW1hZ2U6OkV4aWZUb29sIDEwLjEyJz4KPHJkZjpSREYgeG1sbnM6cmRmPSdodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjJz4KCiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0nJwogIHhtbG5zOmRjPSdodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyc+CiAgPGRjOmRlc2NyaXB0aW9uPgogICA8cmRmOkFsdD4KICAgIDxyZGY6bGkgeG1sOmxhbmc9J3gtZGVmYXVsdCc+SWxsdXN0cmF0aW9uIG9mIHVzZXIgYXZhdGFyIGljb248L3JkZjpsaT4KICAgPC9yZGY6QWx0PgogIDwvZGM6ZGVzY3JpcHRpb24+CiAgPGRjOmZvcm1hdD5pbWFnZS9qcGVnPC9kYzpmb3JtYXQ+CiAgPGRjOnN1YmplY3Q+CiAgIDxyZGY6QmFnPgogICAgPHJkZjpsaT5hY2NvdW50PC9yZGY6bGk+CiAgICA8cmRmOmxpPmF2YXRhcjwvcmRmOmxpPgogICAgPHJkZjpsaT5jb21tdW5pY2F0aW9uPC9yZGY6bGk”
 *   }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *    {
 *        "status": 200,
 *        "isDisplayMessage": true,
 *        "message": "Update User Profile Pic",
 *        "recordList": {
 *            "fieldCount": 0,
 *            "affectedRows": 1,
 *            "insertId": 0,
 *            "serverStatus": 2,
 *            "warningCount": 0,
 *            "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
 *            "protocol41": true,
 *            "changedRows": 1
 *        },
 *        "totalRecords": 1,
 *        "token": ""
 *    }
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
router.post('/updateUserProfilePic', controller.updateUserProfilePic);

// #region /api/app/users/updateUserProfileDetail apidoc
/**
 * @api {post} /api/app/users/updateUserProfileDetail Update Users Profile Detail
 * @apiVersion 1.0.0
 * @apiName Update Users Profile Detail
 * @apiDescription Update Users Profile Detail
 * @apiGroup Users - App
 * @apiParam  {Number}          id                              Requires User id.
 * @apiParam  {String}          firstName                       Requires User firstName.
 * @apiParam  {String}          lastName                        Requires User lastName.
 * @apiParam  {String}          contactNo                       Requires User contactNo.
 * @apiParam  {String}          email                           Requires User email.
 * @apiParam  {String}          gender                          Requires User gender.
 * @apiParam  {String}          addressline1                    Requires User addressline1.
 * @apiParam  {Number}          pincode                         Requires User pincode.
 * @apiParam  {Number}          cityId                          Requires User cityId.
 * @apiParam  {Number}          stateId                         Requires User stateId.
 * @apiParam  {Number}          countryId                       Requires User countryId.
 * @apiParam  {Number}          religionId                      Requires User religionId.
 * @apiParam  {Number}          communityId                     Requires User communityId.
 * @apiParam  {Number}          maritalStatusId                 Requires User maritalStatusId.
 * @apiParam  {Number}          occupationId                    Requires User occupationId.
 * @apiParam  {Number}          educationId                     Requires User educationId.
 * @apiParam  {Number}          annualIncomeId                  Requires User annualIncomeId.
 * @apiParam  {Number}          heightId                        Requires User heightId.
 * @apiParam  {date}            birthDate                       Requires User birthDate.
 * @apiParam  {Number}          employmentTypeId                Requires User employmentTypeId.
 * @apiParam  {String}          companyName                     User companyName.
 * @apiParam  {String}          businessName                    User businessName.
 * @apiParam  {String}          expection                       User expection.
 * @apiParam  {String}          aboutMe                         User aboutMe.
 * @apiParamExample {json} Request-Example:
 * {
 *     "id": 52,
 *     "firstName": "Dipa",
 *     "middleName": "Mohan",
 *     "lastName": "Mishra",
 *     "contactNo":  "3698524789",
 *     "email": "dipa123@gmail.com",
 *     "gender": "Male",
 *     "birthDate": "1967-07-12",
 *     "eyeColor": "Black",
 *     "languages": "Gujarati",
 *     "addressLine1": "Vadodara",
 *     "addressLine2": "Surat",
 *     "pincode": "380058",
 *     "countryId": "1",
 *     "cityId": "4",
 *     "stateId": "2",
 *     "maritalStatusId": "1",
 *     "religionId": "5",
 *     "communityId": "2",
 *     "occupationId": "4",
 *     "educationId": "2",
 *     "subCommunityId": "2",
 *     "annualIncomeId": "4",
 *     "dietId": "3",
 *     "heightId": "2"
 *     "businessName": "xyz"
 *     "companyName": "pqr"
 *     "employmentTypeId": "1",
 *     "expection": "sdfdbggbf",
 *     "aboutMe": "dgfbfv"
 *  }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Update User Personal Detail",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "(Rows matched: 1  Changed: 0  Warnings: 0",
 *              "protocol41": true,
 *              "changedRows": 0
 *          },
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
router.post('/updateUserProfileDetail', controller.updateUserProfileDetail);

// #region /api/app/users/forgotPassword apidoc
/**
 * @api {post} /api/app/users/forgotPassword Forgot Password
 * @apiVersion 1.0.0
 * @apiName Forgot Password
 * @apiDescription Forgot Password
 * @apiGroup Users - App
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

// #region /api/app/users/verifyforgotPasswordLink apidoc
/**
 * @api {post} /api/app/users/verifyforgotPasswordLink Verify Forgort Password Link
 * @apiVersion 1.0.0
 * @apiName Verify Forgort Password Link
 * @apiDescription Verify Forgort Password Link
 * @apiGroup Users - App
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

// #region /api/app/users/resetPassword apidoc
/**
 * @api {post} /api/app/users/resetPassword Reset Password
 * @apiVersion 1.0.0
 * @apiName Reset Password
 * @apiDescription Reset Password
 * @apiGroup Users - App
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

// #region /api/app/users/changePassword apidoc
/**
 * @api {post} /api/app/users/changePassword Change Password
 * @apiVersion 1.0.0
 * @apiName Change Password
 * @apiDescription Change Password
 * @apiGroup Users - App
 * @apiParam        {string}            oldPassword               Require oldEmail of users.
 * @apiParam        {string}            newPassword               Require newEmail of users.
 * @apiParamExample {json} Request-Example:
 *    {
 *        "oldPassword": "dip123",
 *        "newPassword": "dipa987"
 *    }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Password Change successfully!",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
 *              "protocol41": true,
 *              "changedRows": 1
 *          },
 *          "totalRecords": 1,
 *          "token": "null"
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
router.post('/changePassword', controller.changePassword);

// #region /api/app/users/changeEmail apidoc
/**
 * @api {post} /api/app/users/changeEmail Change Email
 * @apiVersion 1.0.0
 * @apiName Change Email
 * @apiDescription Change Email
 * @apiGroup Users - App
 * @apiParam        {string}            oldEmail                Require oldEmail of users.
 * @apiParam        {string}            newEmail                Require newEmail of users.
 * @apiParamExample {json} Request-Example:
 *  {
 *       "oldEmail": "dipa@gmail.com",
 *       "newEmail": "dipa123@gmail.com"
 *    }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Email Change successfully!",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
 *              "protocol41": true,
 *              "changedRows": 1
 *          },
 *          "totalRecords": 1,
 *          "token": "null"
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
router.post('/changeEmail', controller.changeEmail);

// #region /api/app/users/changeContact apidoc
/**
 * @api {post} /api/app/users/changeContact Change Contact
 * @apiVersion 1.0.0
 * @apiName Change Contact
 * @apiDescription Change Contact
 * @apiGroup Users - App
 * @apiParam        {string}            oldContact                Require oldContact of users.
 * @apiParam        {string}            newContact                Require newContact of users.
 * @apiParamExample {json} Request-Example:
 *  {
 *       "oldContact": "321456987",
 *       "newContact": "654987123"
 *    }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Contact Change successfully!",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
 *              "protocol41": true,
 *              "changedRows": 1
 *          },
 *          "totalRecords": 1,
 *          "token": "null"
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
router.post('/changeContact', controller.changeContact);

// #region /api/app/users/searchUser apidoc
/**
 * @api {post} /api/app/users/searchUser Get Search User
 * @apiVersion 1.0.0
 * @apiName Get Search User
 * @apiDescription Get Search User
 * @apiGroup Users - App
 * @apiParamExample {json} Request-Example:
 *      {
 *          "name": "Rahul",
 *          "gender": "Male",
 *          "occupationId": "4",
 *          "educationId": "3",
 *          "heightId": "1",
 *          "maritalStatusId": "1",
 *          "cityName": "Surat",
 *          "state": "1",
 *          "age1": "18",
 *          "age2": "28"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Search User Successfully",
 *         "recordList": [
 *             {
 *                 "id": 5,
 *                 "userId": 22,
 *                 "imageUrl": "content/user/22/26.jpeg",
 *                 "firstName": "Rahul",
 *                 "middleName": null,
 *                 "lastName": "Gamit",
 *                 "contactNo": "3265478912",
 *                 "email": "rahul123@gmail.com",
 *                 "gender": "Male",
 *                 "birthDate": "1995-09-23T18:30:00.000Z",
 *                 "age": 27,
 *                 "eyeColor": "Black",
 *                 "languages": "Gujarati",
 *                 "addressLine1": "Gangadhara",
 *                 "addressLine2": "Bardoli",
 *                 "pincode": "380058",
 *                 "cityName": "Bopal",
 *                 "state": "GUJARAT",
 *                 "maritalStatus": "Married",
 *                 "religion": "Sikh",
 *                 "community": "Trivedi",
 *                 "occupation": "Designer",
 *                 "education": "B pharm",
 *                 "subCommunity": "Brahmin",
 *                 "annualIncome": "4 lakh",
 *                 "diet": "Jain",
 *                 "height": "130 cm"
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
router.post('/searchUser', controller.searchUser);

// #region /api/app/users/updateUserFlagValues apidoc
/**
 * @api {post} /api/app/users/updateUserFlagValues Update User Flag Values
 * @apiVersion 1.0.0
 * @apiName Update User Flag Values
 * @apiDescription Update User Flag Values
 * @apiGroup Users - App
 * @apiParam        {number}                     id                              Require id of users.
 * @apiParam        {number}                     userFlagId                      Require userFlagId of users.
 * @apiParam        {boolean}                     userFlagValue                   Require userFlagValue of users.
 * @apiParamExample {json} Request-Example:
 *  {
 *       "id": "1",
 *       "userFlagId": "1"
 *       "userFlagValue": "True"
 *    }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Update User Flag Value successfully!",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
 *              "protocol41": true,
 *              "changedRows": 1
 *          },
 *          "totalRecords": 1,
 *          "token": "null"
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
router.post('/updateUserFlagValues', controller.updateUserFlagValues);

// #region /api/app/users/validateAuthToken apidoc
/**
 * @api {post} /api/app/users/validateAuthToken check user token
 * @apiVersion 1.0.0
 * @apiName Update User Flag Values
 * @apiDescription Update User Flag Values
 * @apiGroup Users - App
 * @apiParam        {number}                     id                              Require id of users.
 * @apiParam        {number}                     userFlagId                      Require userFlagId of users.
 * @apiParam        {boolean}                     userFlagValue                   Require userFlagValue of users.
 * @apiParamExample {json} Request-Example:
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Update User Flag Value successfully!",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "(Rows matched: 1  Changed: 1  Warnings: 0",
 *              "protocol41": true,
 *              "changedRows": 1
 *          },
 *          "totalRecords": 1,
 *          "token": "null"
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
router.post('/validateAuthToken', controller.validateAuthToken);

export = router;