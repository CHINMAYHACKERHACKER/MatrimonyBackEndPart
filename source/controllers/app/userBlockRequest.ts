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
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let sql = `SELECT ubr.*, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl FROM userblockrequest ubr
                LEFT JOIN users u ON u.id = ubr.blockRequestUserId
                LEFT JOIN images img ON img.id = u.imageId
                WHERE ubr.userId = ` + userId + ` AND ubr.isDelete = 0`;
                if (startIndex != null && fetchRecord != null) {
                    sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                }
                let result = await query(sql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get Proposals Got By me Successfully', result, result.length, authorizationResult.token);
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

const insertUserBlockRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting User Block Request');
        let requiredFields = ['blockRequestUserId', 'reason'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                req.body.reason = req.body.reason ? req.body.reason : '';
                let sql = `INSERT INTO userblockrequest(userId, blockRequestUserId, reason, createdBy, modifiedBy) VALUES(` + userId + `,` + req.body.blockRequestUserId + `,'` + req.body.reason + `',` + userId + `,` + userId + `)`;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Insert User Block Request', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "userBlockRequest.insertUserBlockRequest() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'userBlockRequest.insertUserBlockRequest() Exception', error, '');
        next(errorResult);
    }
};

const removeUserBlockRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Remove User Block Request');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `DELETE FROM userblockrequest WHERE id = ` + req.body.id + ``;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Remove User Block Request', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "userBlockRequest.removeUserBlockRequest() Error", new Error('Error While Deleting Data'), '');
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
        let errorResult = new ResultError(500, true, 'userBlockRequest.removeUserBlockRequest() Exception', error, '');
        next(errorResult);
    }
};

export default { getUserBlockRequest, insertUserBlockRequest, removeUserBlockRequest };