import { NextFunction, Request, Response } from 'express';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';

const mysql = require('mysql');
const util = require('util');
const fs = require('fs');
const sharp = require('sharp');

let connection = mysql.createConnection({
    host: config.mysql.host,
    user: config.mysql.user,
    password: config.mysql.password,
    database: config.mysql.database
});

const query = util.promisify(connection.query).bind(connection);

const NAMESPACE = 'Success Stories';

const getSuccessStories = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Success Stories');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) { 
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let sql = `SELECT s.*, img.imageUrl, u.firstName as userFName, u.lastName as userLName, u.gender as userGender, u.email as userEmail, img1.imageUrl as userImage, addr.cityName as userCity, u1.firstName as partnerFName, u1.lastName as partnerLName, u1.gender as partnerGender, u1.email as partnerEmail, img2.imageUrl as partnerImage, addr1.cityName as partnerCity FROM successstories s
            LEFT JOIN images img ON img.id = s.imageId
            LEFT JOIN users u ON u.id = s.userId
            LEFT JOIN users u1 ON u1.id = s.partnerUserId 
            LEFT JOIN images img1 ON img1.id = u.imageId
            LEFT JOIN images img2 ON img2.id = u1.imageId
            LEFT JOIN userpersonaldetail upd ON upd.userId = s.userId
            LEFT JOIN addresses addr ON addr.id = upd.addressId
            LEFT JOIN userpersonaldetail upd1 ON upd1.userId = s.partnerUserId
            LEFT JOIN addresses addr1 ON addr1.id = upd1.addressId `;
            if(req.body.searchId) {
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` s.userId = ` + req.body.searchId + ` OR s.parentId = ` + req.body.searchId + ` `;
            }
            if (req.body.dateTo && req.body.dateFrom) {
                let toDate = new Date(req.body.dateTo).getFullYear() + "-" + ("0" + (new Date(req.body.dateTo).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.dateTo).getDate()).slice(-2);
                let fromDate = new Date(req.body.dateFrom).getFullYear() + "-" + ("0" + (new Date(req.body.dateFrom).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.dateFrom).getDate()).slice(-2);
                if (!sql.includes("WHERE")) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` DATE(s.createdDate) >= DATE('` + fromDate + `') AND DATE(s.createdDate) <= DATE('` + toDate + `') `;
            }
            if(req.body.maritalStatus) {
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` s.maritalStatus like '%` + req.body.maritalStatus + `%' `;
            }
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if(result) {
                let successResult = new ResultSuccess(200, true, 'Get Success Stories Successfully', result, result.length, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "successStories.getSuccessStories() Error", new Error('Error While Getting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'successStories.getSuccessStories() Exception', error, '');
        next(errorResult);
    }
};

const activeInactiveSuccessStories = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Active Inactive Success Stories');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let sql = `UPDATE successstories set isActive = !isActive WHERE id = ` + req.body.id + ``;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Change Success Stories Status', result, 1, authorizationResult.token);
                    return res.status(200).send(successResult);
                }
                else {
                    let errorResult = new ResultError(400, true, "successStories.activeInactiveSuccessStories() Error", new Error('Error While Change Annual Income Status'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'successStories.activeInactiveSuccessStories() Exception', error, '');
        next(errorResult);
    }
};

export default { getSuccessStories, activeInactiveSuccessStories };