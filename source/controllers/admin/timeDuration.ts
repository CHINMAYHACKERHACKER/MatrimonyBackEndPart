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

const NAMESPACE = 'Time Duration';

const getTimeDuration = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Time Duration');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = "SELECT COUNT(*) as totalCount  FROM timeduration";
            let countResult = await query(countSql);
            let sql = `SELECT * FROM timeduration WHERE isDelete = 0 ORDER BY value ASC`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Time Duration Successfully', result, countResult[0].totalCount, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'timeDuration.getTimeDuration() Exception', error, '');
        next(errorResult);
    }
};

const insertUpdateTimeDuration = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Updating Time Duration');
        let requiredFields = ['value'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let checkSql = `SELECT * FROM timeduration WHERE value = '` + req.body.value + `'`;
                if (req.body.id) {
                    checkSql += ' AND id != ' + req.body.id;
                }
                let checkResult = await query(checkSql);
                if (checkResult && checkResult.length > 0) {
                    let errorResult = new ResultError(400, true, "", new Error("Value Already Exist"), '');
                    next(errorResult);
                } else {
                    if (req.body.id) {
                        let sql = `UPDATE timeduration SET value = '` + req.body.value + `' where id = ` + req.body.id + ``;
                        let result = await query(sql);
                        if (result && result.affectedRows > 0) {
                            let successResult = new ResultSuccess(200, true, 'Update Time Duration', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);
                        } else {
                            let errorResult = new ResultError(400, true, "timeDuration.insertUpdateTimeDuration() Error", new Error('Error While Updating Data'), '');
                            next(errorResult);
                        }
                    } else {
                        let sql = `INSERT INTO timeduration(value, createdBy, modifiedBy) VALUES('` + req.body.value + `',` + userId + `,` + userId + `);`;
                        let result = await query(sql);
                        if (result && result.affectedRows > 0) {
                            let successResult = new ResultSuccess(200, true, 'Insert Time Duration', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);
                        } else {
                            let errorResult = new ResultError(400, true, "timeDuration.insertUpdateTimeDuration() Error", new Error('Error While Inserting Data'), '');
                            next(errorResult);
                        }
                    }
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
        let errorResult = new ResultError(500, true, 'timeDuration.insertUpdateTimeDuration() Exception', error, '');
        next(errorResult);
    }
};

const activeInactiveTimeDuration = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Active Inactive Time Duration');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let checkSql = `SELECT * FROM packageduration WHERE timeDurationId = ` + req.body.id;
                let sqlResult = await query(checkSql);
                if (sqlResult && sqlResult.length > 0) {
                    let result: any = 'You are not able to Change Status this Time Duration.';
                    let successResult = new ResultSuccess(200, true, 'Change Time Duration Status', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let sql = `UPDATE timeduration set isActive = !isActive WHERE id = ` + req.body.id + ``;
                    let result = await query(sql);
                    if (result && result.affectedRows > 0) {
                        let successResult = new ResultSuccess(200, true, 'Change Time Duration Status', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    }
                    else {
                        let errorResult = new ResultError(400, true, "timeDuration.activeInactiveTimeDuration() Error", new Error('Error While Change Time Duration Status'), '');
                        next(errorResult);
                    }
                }
            }
            else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'timeDuration.activeInactiveTimeDuration() Exception', error, '');
        next(errorResult);
    }
};

const deleteTimeDuration = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Active Inactive Time Duration');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let checkSql = `SELECT * FROM packageduration WHERE timeDurationId = ` + req.body.id;
                let sqlResult = await query(checkSql);
                if (sqlResult && sqlResult.length > 0) {
                    let result: any = 'You are not able to Delete this Time Duration.';
                    let successResult = new ResultSuccess(200, true, 'Delete Time Duration', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let sql = `DELETE FROM timeduration WHERE id = ` + req.body.id + ``;
                    let result = await query(sql);
                    if (result && result.affectedRows > 0) {
                        let successResult = new ResultSuccess(200, true, 'Delete Time Duration', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    }
                    else {
                        let errorResult = new ResultError(400, true, "timeDuration.deleteTimeDuration() Error", new Error('Error While Change Occupation Status'), '');
                        next(errorResult);
                    }
                }
            }
            else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'timeDuration.deleteTimeDuration() Exception', error, '');
        next(errorResult);
    }
};

export default { getTimeDuration, insertUpdateTimeDuration, activeInactiveTimeDuration, deleteTimeDuration };