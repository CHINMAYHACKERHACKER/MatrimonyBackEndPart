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

const NAMESPACE = 'Payment';

const insertPaymentRazorpay = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Payment');
        let requiredFields = ['paymentReference', 'paymentStatus', 'amount', 'signature', 'orderId', 'paymentMode'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let sql = `INSERT INTO payment (paymentMode,paymentRefrence,amount,userId,paymentStatus,signature,orderId,createdBy, modifiedBy) 
                VALUES('`+ req.body.paymentMode + `','` + req.body.paymentReference + `',` + req.body.amount + `,` + userId + `,'` + req.body.paymentStatus + `','` + req.body.signature + `','` + req.body.orderId + `',` + userId + `,` + userId + `)`
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Inserting Payment', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "payment.insertPaymentRazorpay() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'payment.insertPaymentRazorpay() Exception', error, '');
        next(errorResult);
    }
}

const insertPaymentStripe = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Inserting Payment');
        let requiredFields = ['amount', 'paymentStatus', 'paymentMode', 'paymentReference'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let sql = `INSERT INTO payment (paymentMode,paymentRefrence,amount,userId,paymentStatus,createdBy, modifiedBy) 
                VALUES('`+ req.body.paymentMode + `','` + req.body.paymentReference + `',` + req.body.amount + `,` + userId + `,'` + req.body.paymentStatus + `',` + userId + `,` + userId + `)`
                let result = await query(sql);
                console.log(result)
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Inserting Payment', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "payment.insertPaymentStripe() Error", new Error('Error While Updating Data'), '');
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
        let errorResult = new ResultError(500, true, 'payment.insertPaymentStripe() Exception', error, '');
        next(errorResult);
    }
}

export default { insertPaymentRazorpay, insertPaymentStripe };