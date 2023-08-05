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

const NAMESPACE = 'App Users';

const getAppUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting App Users');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = `SELECT COUNT(*) as totalCount FROM users
                            LEFT JOIN userroles ur ON ur.userId = users.id
                            WHERE users.isDelete = 0 AND ur.roleId = 2 AND users.firstName IS NOT NULL`;
            if (req.body.searchString) {
                if (!countSql.includes(` WHERE `)) {
                    countSql += ` WHERE `;
                } else {
                    countSql += ` AND `;
                }
                countSql += ` (users.firstName LIKE '%` + req.body.searchString + `%' OR users.lastName LIKE '%` + req.body.searchString + `%' OR users.email LIKE '%` + req.body.searchString + `%' OR users.contactNo LIKE '%` + req.body.searchString + `%' OR users.gender LIKE '%` + req.body.searchString + `%')`;
            }
            let countResult = await query(countSql);
            let sql = ` SELECT users.*,i.imageUrl as imageUrl, ur.roleId as roleId FROM users
                        LEFT JOIN userroles ur ON ur.userId = users.id
                        LEFT JOIN images i ON  i.id = users.imageId
                        WHERE users.isDelete = 0 AND ur.roleId = 2 AND users.firstName IS NOT NULL`;
            if (req.body.searchString) {
                if (!sql.includes(` WHERE `)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` (users.firstName LIKE '%` + req.body.searchString + `%' OR users.lastName LIKE '%` + req.body.searchString + `%' OR users.email LIKE '%` + req.body.searchString + `%' OR users.contactNo LIKE '%` + req.body.searchString + `%' OR users.gender LIKE '%` + req.body.searchString + `%') `;
            }
            sql += ` ORDER BY users.id DESC`
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get App Users Successfully', result, countResult[0].totalCount, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'appUsers.getAppUsers() Exception', error, '');
        next(errorResult);
    }
};

const viewAppUserPerDetail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, upd.birthDate, upd.languages, upd.eyeColor, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, cou.name as country, em.name, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS Age FROM users u
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id = u.imageId
                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                LEFT JOIN religion r ON r.id = upd.religionId
                LEFT JOIN maritalstatus ms ON ms.id = upd.maritalStatusId
                LEFT JOIN community c ON c.id = upd.communityId
                LEFT JOIN occupation o ON o.id = upd.occupationId
                LEFT JOIN education e ON e.id = upd.educationId
                LEFT JOIN subcommunity sc ON sc.id = upd.subCommunityId
                LEFT JOIN annualincome ai ON ai.id = upd.annualIncomeId
                LEFT JOIN diet d ON d.id = upd.dietId
                LEFT JOIN height h ON h.id = upd.heightId
                LEFT JOIN addresses addr ON addr.id = upd.addressId
                LEFT JOIN cities cit ON addr.cityId = cit.id
                LEFT JOIN state st ON addr.stateId = st.id
                LEFT JOIN countries cou ON addr.countryId = cou.id
                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                WHERE ur.roleId = 2 AND u.id = ` + req.body.userId;
                let result = await query(userPerDetailSql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, result.length, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewAppUserDetail() Error", new Error('Error While Getting Data'), '');
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
        let errorResult = new ResultError(500, true, 'appUsers.viewAppUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const viewAppUserSendRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT count(id) as totalRecords FROM userproposals
                WHERE userId = ` + req.body.userId;
                let countResult = await query(countSql);
                let proSendReqSql = `SELECT up.*, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl FROM userproposals up
                LEFT JOIN users u ON u.id = up.proposalUserId
                LEFT JOIN images img ON img.id = u.imageId
                WHERE up.isDelete = 0 And up.userId = ` + req.body.userId;
                if (startIndex != null && fetchRecord != null) {
                    proSendReqSql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                }
                let result = await query(proSendReqSql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, countResult[0].totalRecords, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewAppUserDetail() Error", new Error('Error While Getting Data'), '');
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
        let errorResult = new ResultError(500, true, 'appUsers.viewAppUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const viewAppUserGotRequest = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT count(id) as totalRecords FROM userproposals
                WHERE proposalUserId = ` + req.body.userId;
                let countResult = await query(countSql);
                let propGotReqSql = `SELECT up.*, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl FROM userproposals up
                LEFT JOIN users u ON u.id = up.userId
                LEFT JOIN images img ON img.id = u.imageId
                WHERE up.isDelete = 0 And up.proposalUserId = ` + req.body.userId;
                if (startIndex != null && fetchRecord != null) {
                    propGotReqSql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                }
                let result = await query(propGotReqSql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, countResult[0].totalRecords, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewAppUserDetail() Error", new Error('Error While Getting Data'), '');
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
        let errorResult = new ResultError(500, true, 'appUsers.viewAppUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const viewAppUserFavourites = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT count(id) as totalRecords FROM userfavourites
                WHERE userId = ` + req.body.userId;
                let countResult = await query(countSql);
                let favSql = `SELECT uf.*, u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl FROM userfavourites uf
                LEFT JOIN users u ON u.id = uf.favUserId
                LEFT JOIN images img ON img.id = u.imageId
                WHERE uf.isDelete = 0 And uf.userId = ` + req.body.userId;
                if (startIndex != null && fetchRecord != null) {
                    favSql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                }
                let result = await query(favSql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, countResult[0].totalRecords, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewAppUserDetail() Error", new Error('Error While Getting Data'), '');
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
        let errorResult = new ResultError(500, true, 'appUsers.viewAppUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const viewBlockUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Proposal');
        let requiredFields = ['userId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT count(id) as totalRecords FROM userblock
                WHERE userId = ` + req.body.userId;
                let countResult = await query(countSql);
                let blockReqSql = `select ub.*,u.firstName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl from userblock ub 
                left join users u on u.id = ub.userblockId
                left join images img on u.imageId = img.id
                where userId = ` + req.body.userId;
                if (startIndex != null && fetchRecord != null) {
                    blockReqSql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                }
                let result = await query(blockReqSql);
                if (result) {
                    let successResult = new ResultSuccess(200, true, 'Get App User Detail Successfully', result, countResult[0].totalRecords, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, "appUsers.viewBlockUser() Error", new Error('Error While Getting Data'), '');
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
        let errorResult = new ResultError(500, true, 'appUsers.viewBlockUser() Exception', error, '');
        next(errorResult);
    }
};

const unblockUserRequest = async (req: Request, res: Response, next: NextFunction) => {
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
                let sql = `UPDATE userblockrequest SET status = ` + req.body.status + ` WHERE blockRequestUserId = ` + req.body.id;
                result = await query(sql);

                let updateSql = `UPDATE users SET isDisable = ` + req.body.status + `, modifiedDate = CURRENT_TIMESTAMP WHERE id =` + req.body.id;
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

export default { getAppUsers, viewAppUserPerDetail, viewAppUserSendRequest, viewAppUserGotRequest, viewAppUserFavourites, unblockUserRequest, viewBlockUser }