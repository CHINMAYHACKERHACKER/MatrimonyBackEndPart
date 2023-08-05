import express from 'express';
import controller from '../../controllers/app/userFavourites';

const router = express.Router();

// #region /api/app/favourites/getUserFavourites apidoc
/**
 * @api {post} /api/app/favourites/getUserFavourites Get Favourites
 * @apiVersion 1.0.0
 * @apiName Get Favourites
 * @apiDescription Get Favourites
 * @apiGroup Favourites - App
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *    {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Favourites Users Successfully",
 *         "recordList": [
 *             {  
 *                 "id": 1,
 *                 "userId": 22,
 *                 "favUserId": 25,
 *                 "firstName": "Bhavin",
 *                 "lastName": "Panchal",
 *                 "gender": "Male",
 *                 "email": "bhavin123@gmail.com",
 *                 "contactNo": "3265478912",
 *                 "image": null,
 *                 "isBlockByMe": 1,
 *                 "isBlockByOther": 0,
 *                 "createdDate": "2022-10-19T05:19:52.000Z"
 *             },...
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
router.post('/getUserFavourites', controller.getUserFavourites);

// #region /api/app/favourites/insertUserFavourites apidoc
/**
 * @api {post} /api/app/favourites/insertUserFavourites Insert UserFavourites
 * @apiVersion 1.0.0
 * @apiName Insert UserFavourites
 * @apiDescription Insert UserFavourites
 * @apiGroup Favourites - App
 * @apiParam  {Number}          favUserId             Requires favUserId of Favourites.
 * @apiParamExample {json} Request-Example:
 * {
 *     "favUserId": 25
 * }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Insert User Favourites",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 6,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "",
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
router.post('/insertUserFavourites', controller.insertUserFavourites);

// #region /api/app/favourites/removeUserFavourites apidoc
/**
 * @api {post} /api/app/favourites/removeUserFavourites Remove UserFavourites
 * @apiVersion 1.0.0
 * @apiName Remove UserFavourites
 * @apiDescription Remove UserFavourites
 * @apiGroup Favourites - App
 * @apiParam  {Number}          id                Requires id of Favourites.
 * @apiParamExample {json} Request-Example:
 * {
 *   "id": 9
 * }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Delete User Favourites",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "",
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
router.post('/removeUserFavourites', controller.removeUserFavourites);

// #region /api/app/favourites/addRemoveFavourite apidoc
/**
 * @api {post} /api/app/favourites/addRemoveFavourite Add Remove Favourites
 * @apiVersion 1.0.0
 * @apiName Add Remove UserFavourites
 * @apiDescription Add Remove UserFavourites
 * @apiGroup Favourites - App
 * @apiParam  {Number}          favUserId                         Requires favUserId of Favourites.
 * @apiParam  {boolean}         isFavourite                       Requires isFavourite of Favourites.
 * @apiParamExample {json} Request-Example:
 * {
 *   "favUserId": 9,
 *   "isFavourite": true
 * }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *          "status": 200,
 *          "isDisplayMessage": true,
 *          "message": "Delete User Favourites",
 *          "recordList": {
 *              "fieldCount": 0,
 *              "affectedRows": 1,
 *              "insertId": 0,
 *              "serverStatus": 2,
 *              "warningCount": 0,
 *              "message": "",
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
router.post('/addRemoveFavourite', controller.addRemoveFavourite);

export = router;