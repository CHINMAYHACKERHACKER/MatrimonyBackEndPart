import express from 'express';
import controller from '../../controllers/admin/cities';

const router = express.Router();

// #region /api/admin/cities/getCities apidoc
/**
 * @api {post} /api/admin/cities/getCities Get Cities
 * @apiVersion 1.0.0
 * @apiName Get Cities
 * @apiDescription Get Cities
 * @apiGroup Cities - Admin
 * @apiParam  {Integer}         stateId                  Requires Cities stateId.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "stateId": 3
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Cities Succesfully",
 *         "recordList": [
 *             {
 *                 "stateId": 3,
 *                 "id": 21546,
 *                 "districtId": 61,
 *                 "name": "A.G.C.R.",
 *                 "pincode": "110002",
 *                 "isActive": 1,
 *                 "isDelete": 0,
 *                 "createdDate": "2022-03-03T06:59:41.000Z",
 *                 "modifiedDate": "2022-03-03T06:59:41.000Z"
 *             },....
 *         ],
 *         "totalRecords": 545,
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
router.post('/getCities', controller.getCities);

// #region /api/admin/cities/getCitiesData apidoc
/**
 * @api {post} /api/admin/cities/getCitiesData Get Cities Data
 * @apiVersion 1.0.0
 * @apiName Get Cities Data
 * @apiDescription Get Cities Data
 * @apiGroup Cities - Admin
 * @apiParam  {string}         city                  Requires Cities city.
 * @apiParamExample {json} Request-Example:
 *      { 
 *           "city": "surat"
 *      }
 * @apiSuccess (200) {JSON} Result status, message, recordList, totalRecords.
 * @apiSuccessExample {json} Success-200-Response:
 *     HTTP/1.1 200 OK
 *     {
 *         "status": 200,
 *         "isDisplayMessage": true,
 *         "message": "Get Cities Succesfully",
 *         "recordList": [
 *             {
 *                 "cityName":"Surat",
 *                 "pincode": 21546,
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
router.post('/getCitiesData', controller.getCitiesData);

export = router;