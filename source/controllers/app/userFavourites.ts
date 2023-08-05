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
const beginTransaction = util.promisify(connection.beginTransaction).bind(connection);
const commit = util.promisify(connection.commit).bind(connection);
const rollback = util.promisify(connection.rollback).bind(connection);

const NAMESPACE = 'Favourite';

const getUserFavourites = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting User Favourites');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let sql = `SELECT uf.id, uf.userId, uf.favUserId, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl as image, o.name as occupation, upd.birthDate, addr.cityName, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upd.birthDate)), '%Y') + 0 AS age,
                u.id IN (select userBlockId from userblock where userId = ` + userId + `) as isBlockByMe ,
                u.id IN (select userId from userblock where userBlockId = ` + userId + `)  as isBlockByOther,
                u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
                (u.id = uf.favUserId) AS isFavourite,
                uf.createdDate
                 FROM userfavourites uf
                LEFT JOIN users u ON u.id = uf.favUserId
                LEFT JOIN images img ON img.id = u.imageId
                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                LEFT JOIN occupation o ON o.id = upd.occupationId
                LEFT JOIN addresses addr ON addr.id = upd.addressId
                WHERE uf.isDelete = 0 AND uf.userId = ` + userId + ` AND (u.id IN (select userBlockId from userblock where userId = ` + userId + `) = 0)`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Favourites Users Successfully', result, result.length, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "favourites.getUserFavourites() Error", new Error('Error While Getting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'favourites.getUserFavourites() Exception', error, '');
        next(errorResult);
    }
};

const insertUserFavourites = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Favourite');
        let requiredFields = ['favUserId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let sql = `INSERT INTO userfavourites(userId, favUserId, createdBy, modifiedBy) VALUES(` + userId + `,` + req.body.favUserId + `,` + userId + `,` + userId + `)`;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Insert User Favourites', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "favourites.insertUserFavourites() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'favourites.insertUserFavourites() Exception', error, '');
        next(errorResult);
    }
};

const removeUserFavourites = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Remove User Favourites');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            if (authorizationResult.statusCode == 200) {
                let sql = `DELETE FROM userfavourites WHERE id = ` + req.body.id + ``;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Remove User Favourites', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "favourites.removeUserFavourites() Error", new Error('Error While Deleting Data'), '');
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
        let errorResult = new ResultError(500, true, 'favourites.removeUserFavourites() Exception', error, '');
        next(errorResult);
    }
};

const addRemoveFavourite = async (req: Request, res: Response, next: NextFunction) => {
    try {
        await beginTransaction();
        logging.info(NAMESPACE, 'Inserting Proposals');
        let requiredFields = ['favUserId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                if (req.body.isFavourite == true) {
                    let sql = `INSERT INTO userfavourites(userId, favUserId, createdBy, modifiedBy) VALUES(` + userId + `,` + req.body.favUserId + `,` + userId + `,` + userId + `)`;
                    let result = await query(sql);
                    if (result && result.affectedRows > 0) {
                        let userFavInsertedId = result.insertId;
                        let user = await query(`SELECT * FROM users where id = ` + userId);
                        user[0].lastName = user[0].lastName ? user[0].lastName : '';
                        let title =user[0].firstName + ' ' + user[0].lastName + ' added you in favourite.';
                        let description =user[0].firstName + ' ' + user[0].lastName + ' added you in favourite.';
                        let fcmToken = "";
                        let dataBody = {
                            type: 1,
                            id: userId,
                            title: title,
                            message: description,
                            json: null,
                            dateTime: null,
                        }
                        let customerFcmSql = "SELECT fcmToken FROM userdevicedetail WHERE userId = " + req.body.favUserId + " ORDER BY id DESC LIMIT 1";
                        let customerFcmResult = await query(customerFcmSql);
                        if (customerFcmResult && customerFcmResult.length > 0) {
                            fcmToken = customerFcmResult[0].fcmToken;
                        }

                        let check = `SELECT uf.id as userflagId , ufv.userId FROM userflags uf
                        LEFT JOIN userflagvalues ufv ON ufv.userId = `+ req.body.favUserId + `
                        WHERE uf.flagName = 'pushNotification' AND ufv.userFlagValue = 1`;
                        let checkResult = await query(check);
                        if (checkResult && checkResult.length > 0) {
                            let notificationRes = await notificationContainer.sendMultipleNotification([fcmToken], userId, title, description, '', null, null, 1);
                            if (notificationRes && notificationRes?.failureCount == 0) {
                                let notificationSql = `INSERT INTO usernotifications(userId, title, message, bodyJson, imageUrl, createdBy, modifiedBy) VALUES(` + req.body.favUserId + `,'` + title + `', '` + description + `', '` + JSON.stringify(dataBody) + `', null, ` + authorizationResult.currentUser.id + `, ` + authorizationResult.currentUser.id + `)`
                                result = await query(notificationSql);
                                if (result && result.insertId > 0) {
                                    await commit();
                                    let successResult = new ResultSuccess(200, true, 'Add Favourite', result, 1, authorizationResult.token);
                                    return res.status(200).send(successResult);
                                } else {
                                    await rollback();
                                    let errorResult = new ResultError(400, true, "favourites.addRemoveFavourite() Error", new Error('Error While Updating Data'), '');
                                    next(errorResult);
                                }
                            } else {
                                await rollback();
                                let errorResult = new ResultError(400, true, "favourites.addRemoveFavourite() Error", new Error('Error While Deleting Data'), '');
                                next(errorResult);
                            }
                        } else {
                            await commit();
                            let successResult = new ResultSuccess(200, true, 'Add Favourite', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);
                        }
                    } else {
                        await rollback();
                        let errorResult = new ResultError(400, true, "favourites.addRemoveFavourite() Error", new Error('Error While Updating Data'), '');
                        next(errorResult);
                    }
                } else {
                    if (req.body.isFavourite == false) {
                        let sql = `DELETE FROM userfavourites WHERE favUserId = ` + req.body.favUserId + ` AND userId = ` + userId + ``;
                        let result = await query(sql);
                        if (result && result.affectedRows > 0) {
                            await commit();
                            let successResult = new ResultSuccess(200, true, 'Remove Favourite', result, 1, authorizationResult.token);
                            return res.status(200).send(successResult);
                        } else {
                            await rollback();
                            let errorResult = new ResultError(400, true, "favourites.addRemoveFavourite() Error", new Error('Error While Deleting Data'), '');
                            next(errorResult);
                        }
                    }
                }
            } else {
                await rollback();
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await rollback();
        let errorResult = new ResultError(500, true, 'favourites.addRemoveFavourite() Exception', error, '');
        next(errorResult);
    }
};

export default { getUserFavourites, insertUserFavourites, removeUserFavourites, addRemoveFavourite }