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

const NAMESPACE = 'User Block Request';

const getUserBlockRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
    logging.info(NAMESPACE, 'Getting User Block Request');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let status = req.body.status;
            let fromDate;
            let toDate;
            if (req.body.toDate != undefined && req.body.fromDate != undefined) {
            fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
            toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            }
            let countSql = `SELECT COUNT(*) as totalCount FROM userblockrequest ubr
            LEFT JOIN users bu ON bu.id = ubr.blockRequestUserId
            LEFT JOIN users u ON u.id = ubr.userId
            WHERE ubr.isDelete = 0 `;
            if (req.body.toDate && req.body.fromDate) {
                countSql += ` AND DATE(ubr.createdDate) >= DATE('` + fromDate + `') AND DATE(ubr.createdDate) <= DATE('` + toDate + `')`;
            }
            if (status && (status).toLowerCase() != 'all') {
                if ((status).toLowerCase() == 'approved') {
                    status = 1;
                } else {
                    if ((status).toLowerCase() == 'rejected') {
                        status = 0;
                    } else {
                        if ((status).toLowerCase() == 'pending') {
                            status = null;
                        }
                    }
                }
                if (!countSql.includes(` WHERE `)) {
                    countSql += ` WHERE `;
                } else {
                    countSql += ` AND `;
                }
                if (status == null) {
                    countSql += ` ubr.status IS NULL `;
                } else {
                    countSql += ` ubr.status = ` + status + ` `;
                }
            }
            if (req.body.blockReqUserName || req.body.userName) {
                if (!countSql.includes(` WHERE `)) {
                    countSql += ` WHERE `;
                } else {
                    countSql += ` AND `;
                }
                countSql += ` (bu.firstName LIKE '%` + req.body.blockReqUserName + `%' OR u.firstName LIKE '%` + req.body.userName + `%') `;
            }
            countSql += ` ORDER BY ubr.id DESC`;
            let countResult = await query(countSql);

            let sql = `SELECT ubr.*, CONCAT(bu.firstName,' ',bu.lastName) as blockReqUserName, CONCAT(u.firstName,' ',u.lastName) as userName FROM userblockrequest ubr
            LEFT JOIN users bu ON bu.id = ubr.blockRequestUserId
            LEFT JOIN users u ON u.id = ubr.userId
            WHERE ubr.isDelete = 0 `;
            if (req.body.toDate && req.body.fromDate) {
                sql += ` AND DATE(ubr.createdDate) >= DATE('` + fromDate + `') AND DATE(ubr.createdDate) <= DATE('` + toDate + `')`;
            }
            if (req.body.status && (req.body.status).toLowerCase() != 'all') {
                if ((req.body.status).toLowerCase() == 'approved') {
                    req.body.status = 1;
                } else {
                    if ((req.body.status).toLowerCase() == 'rejected') {
                        req.body.status = 0;
                    } else {
                        if ((req.body.status).toLowerCase() == 'pending') {
                            req.body.status = null;
                        }
                    }
                }
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                if (req.body.status == null) {
                    sql += ` ubr.status IS NULL `;
                } else {
                    sql += ` ubr.status = ` + req.body.status + ` `;
                }
            }
            if (req.body.blockReqUserName || req.body.userName) {
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` (bu.firstName LIKE '%` + req.body.blockReqUserName + `%' OR u.firstName LIKE '%` + req.body.userName + `%') `;
            }
            sql += ` ORDER BY ubr.id DESC `;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get User Block Request Successfully', result, countResult[0].totalCount, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "userBlockRequest.getUserBlockRequest() Error", new Error('Error While Getting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'userBlockRequest.getUserBlockRequest() Exception', error, '');
        next(errorResult);
    }
};

const updateUserBlockRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Updating User Block Request');
        let requiredFields = ['id', 'status'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let sql = `UPDATE userblockrequest SET status = ` + req.body.status + ` WHERE id = ` + req.body.id;
                result = await query(sql);

                let updateSql = `UPDATE users SET isDisable = ` + req.body.status + `, modifiedDate = CURRENT_TIMESTAMP WHERE id = (SELECT userId from userblockrequest WHERE id = ` + req.body.id+`)`;
                result = await query(updateSql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update User Block Request', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "userBlockRequest.updateUserBlockRequest() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'userBlockRequest.updateUserBlockRequest() Exception', error, '');
        next(errorResult);
    }
};

export default { getUserBlockRequest, updateUserBlockRequest };