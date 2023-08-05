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

const NAMESPACE = 'Question';

const getQuestion = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Question');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null
            let startIndexCategories = req.body.startIndexCategories ? req.body.startIndexCategories : (req.body.startIndexCategories === 0 ? 0 : null)
            let fetchRecordCategories = req.body.fetchRecordCategories ? req.body.fetchRecordCategories : null
            let countSql = `SELECT COUNT(*) as totalCount FROM questioncategories WHERE isDelete = 0`;
            let countResult = await query(countSql);
            let sql = `SELECT * FROM questioncategories WHERE isDelete = 0 ORDER BY id DESC`;
            if (startIndexCategories != null && fetchRecordCategories != null) {
                sql += " LIMIT " + fetchRecordCategories + " OFFSET " + startIndexCategories + " ";
            }
            let result = await query(sql)
            if (result) {
                if (result && result.length) {
                    for (let i = 0; i < result.length; i++) {
                        countSql = `SELECT COUNT(*) as Count from questions q 
                        left join questioncategories qc on qc.id = q.questionCategoriesId
                        where q.questionCategoriesId = ` + result[i].id + ` AND q.isDelete = 0 `;
                        let count = await query(countSql);
                        result[i].questionCount=  count[0].Count;
                        sql = `SELECT q.* from questions q 
                        left join questioncategories qc on qc.id = q.questionCategoriesId
                        where q.questionCategoriesId = ` + result[i].id + ` AND q.isDelete = 0 ORDER BY id DESC`;

                        if (startIndex != null && fetchRecord != null) {
                            sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + " ";
                        }
                        result[i].question = await query(sql);
                    }
                    let successResult = new ResultSuccess(200, true, 'get question successfully', result, countResult[0].totalCount, authorizationResult.token);
                    return res.status(200).send(successResult)
                }
            } else {
                let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data not Available'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'question.getQuestion() Exception', error, '');
        next(errorResult);
    }
}

export default {getQuestion}