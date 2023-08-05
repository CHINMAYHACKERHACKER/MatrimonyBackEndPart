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
const beginTransaction = util.promisify(connection.beginTransaction).bind(connection);
const commit = util.promisify(connection.commit).bind(connection);
const rollback = util.promisify(connection.rollback).bind(connection);

const NAMESPACE = 'Notifications';

const getUserNotifications = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Notifications');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = `SELECT count(*) as totalCount FROM usernotifications WHERE isDelete = 0 AND userId = ` + userId ;
            let countResult = await query(countSql);
            let sql = `SELECT * FROM usernotifications WHERE isDelete = 0 AND userId = ` + userId + ` ORDER BY createdDate DESC`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Notifications Successfully', result, countResult[0].totalCount, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "notifications.getUserNotifications() Error", new Error('Error While Getting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'notifications.getUserNotifications() Exception', error, '');
        next(errorResult);
    }
};

const insertUserNotifications = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Notifications');
        let requiredFields = ['title', 'message'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let sql = `INSERT INTO usernotifications(userId, title, message, createdBy, modifiedBy) VALUES(` + userId + `,'` + req.body.title + `','` + req.body.message + `',` + userId + `,` + userId + `)`;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Insert Occupation', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                }
                else {
                    let errorResult = new ResultError(400, true, "occupation.insertUserNotifications() Error", new Error('Error While Inserting Data'), '');
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
        let errorResult = new ResultError(500, true, 'notifications.insertUserNotifications() Exception', error, '');
        next(errorResult);
    }
};

const deleteUserNotifications = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Delete Notifications');
        // let requiredFields = ['id'];
        // let validationResult = header.validateRequiredFields(req, requiredFields);
        // if (validationResult && validationResult.statusCode == 200) {
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let sql = `DELETE FROM usernotifications WHERE userId = ` + userId + ``;
            if (req.body.id) {
                sql += ` AND id = ` + req.body.id + ` `;
            }
            let result = await query(sql);
            if (result && result.affectedRows > 0) {
                let successResult = new ResultSuccess(200, true, 'Delete User Notifications', result, 1, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "notifications.deleteUserNotifications() Error", new Error('Error While Deleting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
        // } else {
        //     let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
        //     next(errorResult);
        // }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'notifications.deleteUserNotifications() Exception', error, '');
        next(errorResult);
    }
}

export default { getUserNotifications, insertUserNotifications, deleteUserNotifications };