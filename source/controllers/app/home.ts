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

const NAMESPACE = 'Home';

const getOccupation = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Occupation');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let sql = `SELECT * FROM occupation WHERE isDelete = 0`;
            if (req.body.id) {
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` id  = ` + req.body.id + ` `;
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Occupation Successfully', result, result.length, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'home.getOccupation() Exception', error, '');
        next(errorResult);
    }
};

const getLatestProfile = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting All Users');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let sql = `SELECT  u.id, u.firstName, u.middleName, u.lastName, u.gender, u.contactNo, u.email, upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age,  o.name as occupation, img.imageUrl as imageUrl, u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
            u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
             FROM users u
            LEFT JOIN userroles ur ON ur.userId = u.id
            LEFT JOIN images img ON img.id = u.imageId
            LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
            LEFT JOIN occupation o ON o.id = upd.occupationId
            WHERE u.isDelete = 0 ANd ur.roleId = 2 AND u.id != ` + userId + ` AND 
             u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `) AND 
             u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `) AND (upd.userId = u.id)
             order by u.createdDate desc`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Latest Profile Users Successfully', result, result.length, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "home.getAllUsers() Error", new Error('Error While Getting Data'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'home.getAllUsers() Exception', error, '');
        next(errorResult);
    }
};

export default { getLatestProfile, getOccupation }