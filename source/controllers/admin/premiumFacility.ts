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

const NAMESPACE = 'Premiun Facility';

const getPremiumFacility = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Premiun Facility');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = "SELECT COUNT(*) as totalCount  FROM premiumfacility";
            let countResult = await query(countSql);
            let sql = `SELECT * FROM premiumfacility WHERE isDelete = 0 ORDER BY name ASC`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Premium Facility Successfully', result, countResult[0].totalCount, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'premiumFacility.getPremiumFacility() Exception', error, '');
        next(errorResult);
    }
};

const insertUpdatePremiumFacility = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Updating Premiun Facility');
        let requiredFields = ['name'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let checkSql = `SELECT * FROM premiumfacility WHERE name = '` + req.body.name + `'`;
                if (req.body.id) {
                    checkSql += ' AND id != ' + req.body.id;
                }
                let checkResult = await query(checkSql);
                if (checkResult && checkResult.length > 0) {
                    let errorResult = new ResultError(400, true, "", new Error("Name Already Exist"), '');
                    next(errorResult);
                } else {
                    if (req.body.id) {
                        let sql = `UPDATE premiumfacility SET name = '` + req.body.name + `' where id = ` + req.body.id + ``;
                        let result = await query(sql);
                        if (result && result.affectedRows > 0) {
                            let successResult = new ResultSuccess(200, true, 'Update Premiun Facility', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);
                        } else {
                            let errorResult = new ResultError(400, true, "premiumFacility.insertUpdatePremiumFacility() Error", new Error('Error While Updating Data'), '');
                            next(errorResult);
                        }
                    } else {
                        let sql = `INSERT INTO premiumfacility(name, createdBy, modifiedBy) VALUES('` + req.body.name + `',` + userId + `,` + userId + `);`;
                        let result = await query(sql);
                        if (result && result.affectedRows > 0) {
                            let successResult = new ResultSuccess(200, true, 'Insert Premiun Facility', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);
                        } else {
                            let errorResult = new ResultError(400, true, "premiumFacility.insertUpdatePremiumFacility() Error", new Error('Error While Inserting Data'), '');
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
        let errorResult = new ResultError(500, true, 'premiumFacility.insertUpdatePremiumFacility() Exception', error, '');
        next(errorResult);
    }
};

const activeInactivePremiumFacility = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Active Inactive Premiun Facility');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let checkSql = `SELECT * FROM packagefacility WHERE premiumFacilityId = ` + req.body.id;
                let sqlResult = await query(checkSql);
                if (sqlResult && sqlResult.length > 0) {
                    let result: any = 'You are not able to Change this Premiun Facility Status.';
                    // return res.status(200).send(successResult);
                    let successResult = new ResultSuccess(200, true, 'Change Premiun Facility Status', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let sql = `UPDATE premiumfacility set isActive = !isActive WHERE id = ` + req.body.id + ``;
                    let result = await query(sql);
                    if (result && result.affectedRows > 0) {
                        let successResult = new ResultSuccess(200, true, 'Change Premiun Facility Status', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    }
                    else {
                        let errorResult = new ResultError(400, true, "premiumFacility.activeInactivePremiumFacility() Error", new Error('Error While Change  Premiun Facility Status'), '');
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
        let errorResult = new ResultError(500, true, 'premiumFacility.activeInactivePremiumFacility() Exception', error, '');
        next(errorResult);
    }
};

const deletePremiumFacility = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Active Inactive Premiun Facility');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let checkSql = `SELECT * FROM packagefacility WHERE premiumFacilityId = ` + req.body.id;
                let sqlResult = await query(checkSql);
                if (sqlResult && sqlResult.length > 0) {
                    let result: any = 'You are not able to delete this Premium facility.';
                    let successResult = new ResultSuccess(200, true, 'Delete Premiun Facility', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let sql = `DELETE FROM premiumfacility WHERE id = ` + req.body.id;
                    let result = await query(sql);
                    if (result && result.affectedRows > 0) {
                        let successResult = new ResultSuccess(200, true, 'Delete Premiun Facility', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    }
                    else {
                        let errorResult = new ResultError(400, true, "premiumFacility.deletePremiumFacility() Error", new Error('Error While Change Occupation Status'), '');
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
        let errorResult = new ResultError(500, true, 'premiumFacility.deletePremiumFacility() Exception', error, '');
        next(errorResult);
    }
};

export default { getPremiumFacility, insertUpdatePremiumFacility, activeInactivePremiumFacility, deletePremiumFacility };