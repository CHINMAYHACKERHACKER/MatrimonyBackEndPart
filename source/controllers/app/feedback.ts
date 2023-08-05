import { NextFunction, Request, Response } from 'express';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';

const mysql = require('mysql');
const util = require('util');

let connection = mysql.createConnection({
    host: config.mysql.host,
    user: config.mysql.user,
    password: config.mysql.password,
    database: config.mysql.database
});

const query = util.promisify(connection.query).bind(connection);

const NAMESPACE = 'Feedbacks';

const insertFeedback = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Users Feedback');
        let requiredFields = ['userId','description','title'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                req.body.description = req.body.description ? req.body.description : '';
                req.body.title = req.body.title ? req.body.title : '';
                let sql = `INSERT INTO feedback (userId, description, title, createdBy, modifiedBy) VALUES(` + userId + `,'` + req.body.description + `'` +`,'` + req.body.title + `',` + userId + `,` + userId + `)`;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Insert User FeedBack', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "feedback.insertFeedback() Error", new Error('Error While Updating Data'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'feedback.insertFeedback() Exception', error, '');
        next(errorResult);
    }
}

// const getFeedback = async (req: Request, res: Response, next: NextFunction) => {
//     try {
//         logging.info(NAMESPACE, 'Getting Users Feedback');
//         let authorizationResult = await header.validateAuthorization(req, res, next);
//         if (authorizationResult.statusCode == 200) {
//             let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
//             let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
//             let countSql = "SELECT COUNT(*) as totalCount  FROM feedback";
//             let countResult = await query(countSql);
//             let sql = `SELECT * FROM feedback WHERE isDelete = 0 ORDER BY id DESC`;
//             if (startIndex != null && fetchRecord != null) {
//                 sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
//             }
//             let result = await query(sql);
//             if (result && result.length > 0) {
//                 let successResult = new ResultSuccess(200, true, 'Get Feedback Successfully', result, countResult[0].totalCount, authorizationResult.token);
//                 return res.status(200).send(successResult);
//             } else {
//                 let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
//                 next(errorResult);
//             }
//         } else {
//             let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
//             next(errorResult);
//         }
//     } catch (error: any) {
//         let errorResult = new ResultError(500, true, 'feedback.getFeedback() Exception', error, '');
//         next(errorResult);
//     }
// };

export default {insertFeedback};