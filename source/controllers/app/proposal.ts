import { NextFunction, Request, Response } from 'express';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';
import notificationContainer from './../notifications';

const mysql = require('mysql');
const util = require('util');

let connection = mysql.createConnection({
    host: config.mysql.host,
    user: config.mysql.user,
    password: config.mysql.password,
    database: config.mysql.database
});

const query = util.promisify(connection.query).bind(connection);

const NAMESPACE = 'Proposal';

const getProposalsGotByMe = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal Got By Me');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            req.body.status = req.body.status ? req.body.status : null;
            let sql = `SELECT up.id, up.userId, up.proposalUserId, up.status as proposalToMeStatus, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl as image, o.name as occupation, upd.birthDate, addr.cityName, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), birthDate)), '%Y') + 0 AS age,
            u.id IN (select userBlockId from userblock where userId = ` + userId + `)  as isBlockByMe ,
             u.id IN (select userId from userblock where userBlockId = ` + userId + `)  as isBlockByOther,
             up.createdDate
             FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN images img ON img.id = u.imageId
            LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
            LEFT JOIN occupation o ON o.id = upd.occupationId
            LEFT JOIN addresses addr ON addr.id = upd.addressId
            WHERE up.isDelete = 0 AND up.proposalUserId = ` + userId + ` 
            AND (
                u.id IN (select userBlockId from userblock where userId = ` + userId + `) = 0
                AND
                u.id IN (select userId from userblock where userBlockId = ` + userId + `) = 0
                )
            `;
            if (req.body.status == null) {
                sql += ` AND up.status IS NULL `;
            } else {
                sql += ` AND up.status = ` + req.body.status + ` `;
            }
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Proposals Got By me Successfully', result, result.length, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "proposals.getProposalsDetail() Error", new Error('Error While Getting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'proposals.getProposalsDetail() Exception', error, '');
        next(errorResult);
    }
};

const getProposalsSendByMe = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal Send By Me');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let sql = `SELECT up.id, up.userId, up.proposalUserId, up.status, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl as image, o.name as occupation, upd.birthDate, addr.cityName, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upd.birthDate)), '%Y') + 0 AS age,
            u.id IN (select userBlockId from userblock where userId = ` + userId + `)  as isBlockByMe ,
            u.id IN (select userId from userblock where userBlockId = ` + userId + `)  as isBlockByOther,
             up.createdDate
             FROM userproposals up
            LEFT JOIN users u ON u.id = up.proposalUserId
            LEFT JOIN images img ON img.id = u.imageId
            LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
            LEFT JOIN occupation o ON o.id = upd.occupationId
            LEFT JOIN addresses addr ON addr.id = upd.addressId
            WHERE up.isDelete = 0 AND up.userId = ` + userId + ` AND 
            (
                u.id IN (select userBlockId from userblock where userId = ` + userId + `) = 0
                AND
                u.id IN (select userId from userblock where userBlockId = ` + userId + `) = 0
                )`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Proposals Send by me Successfully', result, result.length, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "proposals.getProposalsSendByMe() Error", new Error('Error While Getting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'proposals.getProposalsSendByMe() Exception', error, '');
        next(errorResult);
    }
};

const sendProposals = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Proposals');
        let requiredFields = ['proposalUserId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let sql = `INSERT INTO userproposals(userId, proposalUserId, createdBy, modifiedBy) VALUES(` + userId + `,` + req.body.proposalUserId + `,` + userId + `,` + userId + `)`;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let proposalInsertedId = result.insertId;
                    let user = await query(`SELECT * FROM users where id = ` + userId);
                    user[0].lastName = user[0].lastName ? user[0].lastName : '';
                    let title =user[0].firstName + ' ' + user[0].lastName + ' send a proposal to you.';
                    let description =user[0].firstName + ' ' + user[0].lastName + ' send a proposal to you.';
                    let fcmToken = "";
                    let dataBody = {
                        type: 2,
                        id: userId,
                        title: title,
                        message: description,
                        json: null,
                        dateTime: null,
                    }
                    let customerFcmSql = "SELECT fcmToken FROM userdevicedetail WHERE userId = " + req.body.proposalUserId + " ORDER BY id DESC LIMIT 1";
                    let customerFcmResult = await query(customerFcmSql);
                    if (customerFcmResult && customerFcmResult.length > 0) {
                        fcmToken = customerFcmResult[0].fcmToken;
                    }

                    let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy) VALUES(` + req.body.proposalUserId + `,'` + title + `', '` + description + `', '` + JSON.stringify(dataBody) + `', null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                    let notificationResult = await query(notificationSql);

                    let check = `SELECT uf.id as userflagId , ufv.userId FROM userflags uf
                        LEFT JOIN userflagvalues ufv ON ufv.userId = `+ req.body.proposalUserId + `
                        WHERE uf.flagName = 'pushNotification' AND ufv.userFlagValue = 1`;
                    let checkResult = await query(check);
                    if (checkResult && checkResult.length > 0) {
                        await notificationContainer.sendMultipleNotification([fcmToken], userId, title, description, '', null, null, 2);
                    }

                    let successResult = new ResultSuccess(200, true, 'Insert Us er Proposals', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "proposals.insertUpdateProposals() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'proposals.insertUpdateProposals() Exception', error, '');
        next(errorResult);
    }
};

const acceptRejectProposals = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Proposals');
        let requiredFields = ['id', 'status'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                if (req.body.id) {
                    let updateSql = `UPDATE userproposals SET status = ` + req.body.status + ` WHERE id = ` + req.body.id;
                    let result = await query(updateSql);
                    if (result && result.affectedRows > 0) {
                        let proposal = await query(`SELECT * FROM userproposals WHERE id = ` + req.body.id);
                        let title;
                        let description
                        let fcmToken = "";
                        let dataBody = {
                            type: 3,
                            id: userId,
                            title: title,
                            message: description,
                            json: null,
                            dateTime: null,
                        }
                        let user = await query(`SELECT * FROM users where id = ` + userId);
                        user[0].lastName = user[0].lastName ? user[0].lastName : '';
                        if (req.body.status == true) {
                            title = user[0].firstName + ' ' + user[0].lastName + ' accept your proposal.';
                            description = user[0].firstName + ' ' + user[0].lastName + ' accept your proposal.';
                        } else {
                            title = '' + user[0].firstName + ' ' + user[0].lastName + ' reject your proposal.';
                            description = '' + user[0].firstName + ' ' + user[0].lastName + ' reject your proposal.';
                        }
                        let customerFcmSql = "SELECT fcmToken FROM userdevicedetail WHERE userId = " + proposal[0].userId + " ORDER BY id DESC LIMIT 1";
                        let customerFcmResult = await query(customerFcmSql);
                        if (customerFcmResult && customerFcmResult.length > 0) {
                            fcmToken = customerFcmResult[0].fcmToken;
                        }
                        let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy) VALUES(` + proposal[0].userId + `,'` + title + `', '` + description + `', '` + JSON.stringify(dataBody) + `', null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                        let notificationResult = await query(notificationSql);

                        let check = `SELECT uf.id as userflagId , ufv.userId FROM userflags uf
                        LEFT JOIN userflagvalues ufv ON ufv.userId = `+ proposal[0].userId + `
                        WHERE uf.flagName = 'pushNotification' AND ufv.userFlagValue = 1`;
                        let checkResult = await query(check);
                        if (checkResult && checkResult.length > 0) {
                            await notificationContainer.sendMultipleNotification([fcmToken], userId, title, description, '', null, null, 3);
                        }

                        let successResult = new ResultSuccess(200, true, 'Update User Proposals', result, 1, authorizationResult.token);
                        return res.status(200).send(successResult);
                    } else {
                        let errorResult = new ResultError(400, true, "proposals.insertUpdateProposals() Error", new Error('Error While Updating Data'), '');
                        next(errorResult);
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
        let errorResult = new ResultError(500, true, 'proposals.insertUpdateProposals() Exception', error, '');
        next(errorResult);
    }
};

export default { getProposalsGotByMe, getProposalsSendByMe, sendProposals, acceptRejectProposals };