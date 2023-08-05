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

const NAMESPACE = 'System Flags';

const getAdminSystemFlag = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting SystemFlags');
        let sql = `SELECT * FROM flaggroup WHERE parentFlagGroupId IS NULL`;
        let result = await query(sql);
        if (result && result.length > 0) {
            for (let i = 0; i < result.length; i++) {
                result[i].group = [];
                let innerSql = `SELECT * FROM flaggroup WHERE parentFlagGroupId = ` + result[i].id;
                let innerResult = await query(innerSql);
                if (innerResult && innerResult.length > 0) {
                    result[i].group = innerResult;
                    for (let j = 0; j < result[i].group.length; j++) {
                        result[i].group[j].systemFlag = [];
                        let sysSql = `SELECT * FROM systemflags WHERE isActive = 1 AND flagGroupId = ` + result[i].group[j].id;
                        let sysresult = await query(sysSql);
                        result[i].group[j].systemFlag = sysresult;
                    }
                }
                result[i].systemFlag = [];
                let sysSql = `SELECT * FROM systemflags WHERE  isActive = 1 AND flagGroupId = ` + result[i].id;
                let sysresult = await query(sysSql);
                result[i].systemFlag = sysresult;

            }
        }
        if (result && result.length > 0) {
            let successResult = new ResultSuccess(200, true, 'Get System flag successfully', result, result.length, '');
            return res.status(200).send(successResult);
        } else {
            let errorResult = new ResultError(400, true, "systemflags.getAdminSystemFlag() Error", new Error('Error While Updating Data'), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'systemflags.getAdminSystemFlag() Exception', error, '');
        next(errorResult);
    }
};

const updateSystemFlagByName = async (req: Request, res: Response, next: NextFunction) => {
    try {
        let requiredFields = ['valueList', 'nameList'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let result;
                for (let i = 0; i < req.body.nameList.length; i++) {
                    let sql = "UPDATE systemflags SET value = ? WHERE name = ?";
                    result = await query(sql, [req.body.valueList[i], req.body.nameList[i]]);
                }
                if (result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update System Flag', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "systemflags.updateSystemFlagByName() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'systemflags.updateSystemFlagByName() Exception', error, '');
        next(errorResult);
    }
};

export default { getAdminSystemFlag, updateSystemFlagByName }