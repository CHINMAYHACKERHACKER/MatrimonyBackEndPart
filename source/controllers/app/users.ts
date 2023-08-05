import { NextFunction, request, Request, Response } from 'express';
import bcryptjs from 'bcryptjs';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';
import signJWT from '../../function/signJTW';
import createRefreshToken from '../../function/refreshToken';
import userBlock from './userBlock';
import { Users } from '../../classes/output/admin/users';
import jwt from 'jsonwebtoken';


const mysql = require('mysql');
const util = require('util');
const fs = require('fs');
const sharp = require('sharp');
const crypto = require('crypto');
const nodemailer = require("nodemailer");

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

const NAMESPACE = 'Users';

const verifyEmailContact = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Verify Email and Contact');
        let message = "";
        let sql = `SELECT * FROM users `;
        if (req.body.email) {
            if (!sql.includes(` WHERE `)) {
                sql += ` WHERE `;
            } else {
                sql += ` AND `;
            }
            sql += ` email = '` + req.body.email + `' `;
        }
        if (req.body.contactNo) {
            if (!sql.includes(` WHERE `)) {
                sql += ` WHERE `;
            } else {
                sql += ` OR `;
            }
            sql += ` contactNo = '` + req.body.contactNo + `' `;
        }
        let result = await query(sql);
        if (result && result.length > 0) {
            if (req.body.email && !req.body.contactNo) {
                if (req.body.email == result[0].email) {
                    message = "Email Already Exist";
                }
            }
            if (req.body.contactNo && !req.body.email) {
                if (req.body.contactNo == result[0].contactNo) {
                    message = "ContactNo Already Exist";
                }
            }
            if (req.body.contactNo && req.body.email) {
                if (req.body.email == result[0].email) {
                    message = "Email Already Exist";
                }
                if (req.body.contactNo == result[0].contactNo) {
                    if (message) {
                        message += " and ContactNo Already Exist change both";
                    } else {
                        message = "ContactNo Already Exist";
                    }
                }
            }
            let successResult = new ResultSuccess(200, true, message, result, 1, "null");
            return res.status(200).send(successResult);
        } else {
            let successResult = new ResultSuccess(200, true, message, [], 1, "null");
            return res.status(200).send(successResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.getUsers() Exception', error, '');
        next(errorResult);
    }
};

const getAuthProvider = async (searchString: any) => {
    let result;
    try {
        let sql = "SELECT * FROM authproviders WHERE isActive = 1 AND isDelete = 0";

        if (searchString != undefined) {
            if (!sql.includes("WHERE")) {
                sql += " WHERE ";
            } else {
                sql += " AND ";
            }
            sql += " (providerName LIKE '%" + searchString + "%')";
        }
        result = await query(sql);
        result = JSON.parse(JSON.stringify(result));
    } catch (err) {
        result = err;
    }
    return result;
};

const addUserAuthData = async (body: any) => {
    let result;
    try {
        body.description = body.description ? body.description : '';
        let sql = `INSERT INTO userauthdata (userId, oAuthUserId, oAuthUserName, oAuthUserPicUrl, oAuthAccessToken, authProviderId, description) VALUES (` + body.userId + `,'` + body.oAuthUserId + `','` + body.oAuthUserName + `','` + body.oAuthUserPicUrl + `','` + body.oAuthAccessToken + `',` + body.authProviderId + `,'` + body.description + `')`
        let result = await query(sql);
        if (result.affectedRows > 0) {
            result = JSON.parse(JSON.stringify(result));
        } else {
            result = JSON.parse(JSON.stringify(result));
        }
    } catch (error) {
        return error;
    }
    return result;
};

const updateUserAuthLoginData = async (body: any) => {
    let result;
    try {
        let updatedDate = new Date(new Date().toUTCString());
        let sql = `UPDATE userauthdata SET  oAuthAccessToken =  '` + body.oAuthAccessToken + `', oAuthUserPicUrl = '` + body.oAuthUserPicUrl + `',authProviderId = ` + body.authProviderId + `, modifiedDate = '` + updatedDate + `' WHERE oAuthUserId = '` + body.oAuthUserId + `' AND userId = ` + body.userId + ``;
        result = await query(sql);
        if (result.changedRows > 0) {
            result = JSON.parse(JSON.stringify(result));
        }
    } catch (error: any) {
        return error;
    }
    return result;
};

const signUp = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'SignUp');
        let insertRefTokenResult;
        let deviceDetailResult;
        let requiredFields = ['email', 'contactNo', 'password'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let userDevice = authorizationResult.currentUserDevice;
                let appId: number;
                if (userDevice.app == 'MatrimonyAdmin') {
                    appId = 1;
                } else if (userDevice.app == 'MatrimonyAndroid') {
                    appId = 2;
                } else {
                    appId = 3;
                }
                req.body.imageId = req.body.imageId ? req.body.imageId : null;
                await beginTransaction()
                let checkEmail = `SELECT * FROM users WHERE email = '` + req.body.email + `'`;
                let checkEmailResult = await query(checkEmail);
                if (checkEmailResult && checkEmailResult.length > 0) {
                    await rollback();
                    let successResult = 'Email Already Inserted';
                    return res.status(200).send(successResult);
                } else {
                    bcryptjs.hash(req.body.password, 10, async (hashError, hash) => {
                        if (hashError) {
                            return res.status(401).json({
                                message: hashError.message,
                                error: hashError
                            });
                        }
                        let sql = `INSERT INTO users(contactNo, email, password, isDisable) VALUES (` + req.body.contactNo + `,'` + req.body.email + `','` + hash + `', 0)`;
                        let result = await query(sql);
                        if (result && result.insertId > 0) {
                            let userId = result.insertId;
                            let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 2) `;
                            result = await query(userRoleSql);
                            if (result && result.affectedRows > 0) {
                                if (userDevice) {
                                    userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                    let deviceDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                    deviceDetailResult = await query(deviceDetailSql);
                                }
                                let userFlag = await query(`SELECT * FROM userflags`);
                                if (userFlag && userFlag.length > 0) {
                                    for (let index = 0; index < userFlag.length; index++) {
                                        let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + userId + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                        let userFlagSqlResult = await query(userFlagSql);
                                    }
                                }
                                let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName as cityName, addr.stateName as stateName, addr.countryName as countryName, em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                FROM users u
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
                                 WHERE ur.roleId = 2 AND u.id =  ` + userId + ``;
                                let userResult: any = await query(userPerDetailSql);
                                let signJWTResult: any = await signJWT(userResult[0]);
                                if (signJWTResult && signJWTResult.token) {
                                    userResult[0].token = signJWTResult.token;
                                    let refreshToken = await createRefreshToken(userResult[0]);
                                    //insert refresh token
                                    let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                    insertRefTokenResult = await query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                    if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                        userResult[0].refreshToken = refreshToken.token;

                                        let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                        LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                        WHERE ufv.userId = ` + userId + ``;
                                        userResult[0].userFlags = await query(userflagvalues);

                                        let todayDate = new Date();
                                        let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                        let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                        LEFT JOIN package p ON p.id = up.packageId
                                        LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                        LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                            WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                        let userPackage = await query(userPackages);
                                        if (userPackage && userPackage.length > 0) {
                                            for (let k = 0; k < userPackage.length; k++) {
                                                let packageFacility = await query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                 WHERE pf.packageId = ` + userPackage[k].packageId);
                                                userPackage[k].packageFacility = packageFacility;
                                            }
                                        }
                                        userResult[0].userPackage = userPackage[0];

                                        let minAge = await query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                            FROM users u
                                            LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            LEFT JOIN userroles ur ON ur.userId = u.id
                                            WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                        let maxAge = await query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                            FROM users u
                                            LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            LEFT JOIN userroles ur ON ur.userId = u.id
                                            WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                        let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                        let occupationResult = await query(occupationSql);

                                        let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                        let educationResult = await query(educationSql);

                                        let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                        let maritalStatusResult = await query(maritalStatusSql);

                                        let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                        let religionResult = await query(religionSql);

                                        let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                        let communityResult = await query(communitySql);

                                        let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                        let subCommunityResult = await query(subCommunitySql);

                                        let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                        let dietResult = await query(dietSql);

                                        let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                        let heightResult = await query(heightSql);

                                        let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                        let annualIncomeResult = await query(annualIncomeSql);

                                        let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                        let employmentTypeResult = await query(employmentTypeSql);

                                        userResult[0].masterEntryData = {
                                            "occupation": occupationResult,
                                            "education": educationResult,
                                            "maritalStatus": maritalStatusResult,
                                            "religion": religionResult,
                                            "community": communityResult,
                                            "subCommunity": subCommunityResult,
                                            "diet": dietResult,
                                            "height": heightResult,
                                            "annualIncome": annualIncomeResult,
                                            "employmentType": employmentTypeResult,
                                            "maxAge": maxAge[0].maxAge,
                                            "minAge": minAge[0].minAge
                                        }

                                        await commit();
                                        let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                        return res.status(200).send(successResult);
                                    } else {
                                        await rollback();
                                        let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await rollback();
                                    return res.status(401).json({
                                        message: 'Unable to Sign JWT',
                                        error: signJWTResult.error
                                    });
                                }
                            } else {
                                await rollback();
                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        } else {
                            await rollback();
                            let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                            next(errorResult);
                        }
                    });
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
        let errorResult = new ResultError(500, true, 'users.signUp() Exception', error, '');
        next(errorResult);
    }
};

const login = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Login');
        if (req.body.isOAuth) {
            let requiredFields = ['email'];
            let validationResult = header.validateRequiredFields(req, requiredFields);
            if (validationResult && validationResult.statusCode == 200) {
                let authorizationResult = await header.validateAuthorization(req, res, next);
                if (authorizationResult.statusCode == 200) {
                    let userDevice = authorizationResult.currentUserDevice;
                    let deviceDetailResult;
                    let appId: number;
                    if (userDevice.app == 'MatrimonyAdmin') {
                        appId = 1;
                    } else if (userDevice.app == 'MatrimonyAndroid') {
                        appId = 2;
                    } else {
                        appId = 3;
                    }
                    await beginTransaction();
                    let userId: number;
                    let insertRefTokenResult;

                    let _UserData;
                    let _ValidateUser = await query(`SELECT * FROM users WHERE email = '` + req.body.email + `'`);

                    if (_ValidateUser && _ValidateUser.length <= 0) {
                        let sql = `INSERT INTO users(email, isDisable) VALUES ('` + req.body.email + `', 0)`;
                        let result = await query(sql);
                        if (result && result.insertId > 0) {
                            let userId = result.insertId;
                            let userRoleSql = `INSERT INTO userroles(userId, roleId) VALUES (` + userId + `, 2) `;
                            result = await query(userRoleSql);
                            if (result && result.affectedRows > 0) {
                                if (userDevice) {
                                    userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                    let deviceDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                    deviceDetailResult = await query(deviceDetailSql);
                                }
                                let userFlag = await query(`SELECT * FROM userflags`);
                                if (userFlag && userFlag.length > 0) {
                                    for (let index = 0; index < userFlag.length; index++) {
                                        let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + userId + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                        let userFlagSqlResult = await query(userFlagSql);
                                    }
                                }

                                var authProvider = await getAuthProvider(req.body.oAuthProviderName);
                                if (authProvider.length > 0) {
                                    let data = {
                                        userId: userId,
                                        oAuthUserId: req.body.oAuthUserId,
                                        oAuthUserName: req.body.oAuthUserName,
                                        oAuthUserPicUrl: req.body.oAuthUserPicUrl,
                                        oAuthAccessToken: req.body.oAuthAccessToken,
                                        authProviderId: authProvider[0].id,
                                        description: req.body.description ? req.body.description : ''
                                    };
                                    let userOauthDataResult: any = await addUserAuthData(data);
                                    if (userOauthDataResult && userOauthDataResult.affectedRows <= 0) {
                                        await rollback();
                                    }
                                }

                                let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName as cityName, addr.stateName as stateName, addr.countryName as countryName, em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                    FROM users u
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
                                     WHERE ur.roleId = 2 AND u.id =  ` + userId + ``;
                                let userResult = await query(userPerDetailSql);
                                let signJWTResult: any = await signJWT(userResult[0]);
                                if (signJWTResult && signJWTResult.token) {
                                    userResult[0].token = signJWTResult.token;
                                    let refreshToken = await createRefreshToken(userResult[0]);
                                    //insert refresh token
                                    let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                    insertRefTokenResult = await query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                    if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                        userResult[0].refreshToken = refreshToken.token;

                                        let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                            LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                            WHERE ufv.userId = ` + userId + ``;
                                        userResult[0].userFlags = await query(userflagvalues);

                                        let todayDate = new Date();
                                        let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                        let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                            LEFT JOIN package p ON p.id = up.packageId
                                            LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                            LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                                WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                        let userPackage = await query(userPackages);
                                        if (userPackage && userPackage.length > 0) {
                                            for (let k = 0; k < userPackage.length; k++) {
                                                let packageFacility = await query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                    LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                     WHERE pf.packageId = ` + userPackage[k].packageId);
                                                userPackage[k].packageFacility = packageFacility;
                                            }
                                        }
                                        userResult[0].userPackage = userPackage[0];

                                        let minAge = await query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                                FROM users u
                                                LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                LEFT JOIN userroles ur ON ur.userId = u.id
                                                WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                        let maxAge = await query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                                FROM users u
                                                LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                LEFT JOIN userroles ur ON ur.userId = u.id
                                                WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                        let ageList = [];
                                        for (let i = 18; i <= 60; i++) {
                                            ageList.push(i)
                                        }

                                        let cityName = await query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)

                                        let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                        let occupationResult = await query(occupationSql);

                                        let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                        let educationResult = await query(educationSql);

                                        let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                        let maritalStatusResult = await query(maritalStatusSql);

                                        let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                        let religionResult = await query(religionSql);

                                        let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                        let communityResult = await query(communitySql);

                                        let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                        let subCommunityResult = await query(subCommunitySql);

                                        let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                        let dietResult = await query(dietSql);

                                        let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                        let heightResult = await query(heightSql);

                                        let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                        let annualIncomeResult = await query(annualIncomeSql);

                                        let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                        let employmentTypeResult = await query(employmentTypeSql);

                                        userResult[0].masterEntryData = {
                                            "occupation": occupationResult,
                                            "education": educationResult,
                                            "maritalStatus": maritalStatusResult,
                                            "religion": religionResult,
                                            "community": communityResult,
                                            "subCommunity": subCommunityResult,
                                            "diet": dietResult,
                                            "height": heightResult,
                                            "annualIncome": annualIncomeResult,
                                            "employmentType": employmentTypeResult,
                                            "maxAge": maxAge[0].maxAge,
                                            "minAge": minAge[0].minAge,
                                            "ageList": ageList,
                                            "cityName": cityName
                                        }

                                        await commit();
                                        let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                        return res.status(200).send(successResult);
                                    } else {
                                        await rollback();
                                        let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    await rollback();
                                    return res.status(401).json({
                                        message: 'Unable to Sign JWT',
                                        error: signJWTResult.error
                                    });
                                }
                            } else {
                                await rollback();
                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        } else {
                            await rollback();
                            let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Inserting Data'), '');
                            next(errorResult);
                        }
                    } else {
                        if (req.body.isAppleLogin) {
                            _UserData = await query(`SELECT * FROM userauthdata WHERE oAuthUserId = '` + req.body.oAuthUserId + `'`);
                            userId = _UserData[0].userId
                        } else {
                            _UserData = await query(`SELECT uad.* FROM users u
                                Inner JOIN userauthdata uad ON uad.userId = u.id
                                WHERE u.email = '` + req.body.email + `' AND oAuthUserId = '` + req.body.oAuthUserId + `'`);
                            userId = _UserData[0].id
                        }

                        if (_UserData && _UserData.length <= 0) {
                            _UserData = await query(`SELECT * FROM users WHERE email = '` + req.body.email + `'`);

                            let checkuserflagvalues = await query(`SELECT * FROM userflagvalues WHERE userId = ` + _UserData[0].id);
                            if (checkuserflagvalues && checkuserflagvalues.length <= 0) {
                                let userFlag = await query(`SELECT * FROM userflags`);
                                if (userFlag && userFlag.length > 0) {
                                    for (let index = 0; index < userFlag.length; index++) {
                                        let userFlagSql = `INSERT INTO userflagvalues(userId, userFlagId, userFlagValue) VALUES (` + _UserData[0].id + `, ` + userFlag[index].id + `, ` + userFlag[index].defaultValue + `)`
                                        let userFlagSqlResult = await query(userFlagSql);
                                    }
                                }
                            }

                            var authProvider = await getAuthProvider(req.body.oAuthProviderName);
                            if (authProvider.length > 0) {
                                let data = {
                                    userId: _UserData[0].id,
                                    oAuthUserId: req.body.oAuthUserId,
                                    oAuthUserName: req.body.oAuthUserName,
                                    oAuthUserPicUrl: req.body.oAuthUserPicUrl,
                                    oAuthAccessToken: req.body.oAuthAccessToken,
                                    authProviderId: authProvider[0].id,
                                    description: req.body.description ? req.body.description : ''
                                };
                                let userOauthDataResult: any = await addUserAuthData(data);
                                if (userOauthDataResult && userOauthDataResult.affectedRows <= 0) {
                                    await rollback();
                                }
                            }

                        }
                        else {
                            var authProvider = await getAuthProvider(req.body.oAuthProviderName);
                            if (authProvider.length > 0) {
                                let data = {
                                    oAuthAccessToken: _UserData[0].oAuthAccessToken,
                                    oAuthUserPicUrl: _UserData[0].oAuthUserPicUrl,
                                    oAuthUserId: _UserData[0].oAuthUserId,
                                    userId: _UserData[0].userId,
                                    authProviderId: authProvider[0].id,
                                }
                                await updateUserAuthLoginData(data);
                            }
                        }

                        let result: any = [];
                        result.push(({ "id": _UserData[0].userId }));
                        userId = result[0].id;
                        let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName as cityName, addr.stateName as stateName, addr.countryName as countryName, em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                            FROM users u
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
                             WHERE ur.roleId = 2 AND u.email =  '` + req.body.email + `' `;
                        let userResult = await query(userPerDetailSql);
                        let signJWTResult: any = await signJWT(result[0]);
                        if (signJWTResult && signJWTResult.token) {
                            userResult[0].token = signJWTResult.token;
                            if (userDevice) {
                                let checkDeviceSql = `SELECT * FROM userdevicedetail WHERE userId = ` + userId + ``;
                                result = await query(checkDeviceSql);
                                userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                if (result && result.length > 0) {
                                    let updateDetailSql = `UPDATE userdevicedetail SET userId = ` + userId + `,applicationId = ` + appId + `,deviceId = '` + userDevice.deviceId + `',fcmToken = '` + userDevice.fcmToken + `',deviceLocation = '` + userDevice.deviceLocation + `',deviceManufacturer = '` + userDevice.deviceManufacturer + `',deviceModel = '` + userDevice.deviceModel + `',apiCallTime = '` + userDevice.apiCallTime + `' WHERE userId = ` + userId;
                                    result = await query(updateDetailSql);
                                } else {
                                    let insertDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                    result = await query(insertDetailSql);
                                }
                            }
                            let refreshToken = await createRefreshToken(userResult[0]);
                            //insert refresh token
                            let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                            insertRefTokenResult = await query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                            if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                userResult[0].refreshToken = refreshToken.token;

                                let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                    LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                    WHERE ufv.userId = ` + userId + ``;
                                userResult[0].userFlags = await query(userflagvalues);

                                let todayDate = new Date();
                                let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                    LEFT JOIN package p ON p.id = up.packageId
                                    LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                    LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                        WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                let userPackage = await query(userPackages);
                                if (userPackage && userPackage.length > 0) {
                                    for (let k = 0; k < userPackage.length; k++) {
                                        let packageFacility = await query(`SELECT pf.*, pff.name FROM packagefacility pf
                                            LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                             WHERE pf.packageId = ` + userPackage[k].packageId);
                                        userPackage[k].packageFacility = packageFacility;
                                    }
                                }
                                userResult[0].userPackage = userPackage[0];

                                let minAge = await query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                    FROM users u
                                    LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                    LEFT JOIN userroles ur ON ur.userId = u.id
                                    WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                let maxAge = await query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                    FROM users u
                                    LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                    LEFT JOIN userroles ur ON ur.userId = u.id
                                    WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                let ageList = [];
                                for (let i = 18; i <= 60; i++) {
                                    ageList.push(i)
                                }
                                let cityName = await query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)

                                let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                let occupationResult = await query(occupationSql);

                                let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                let educationResult = await query(educationSql);

                                let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                let maritalStatusResult = await query(maritalStatusSql);

                                let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                let religionResult = await query(religionSql);

                                let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                let communityResult = await query(communitySql);

                                let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                let subCommunityResult = await query(subCommunitySql);

                                let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                let dietResult = await query(dietSql);

                                let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                let heightResult = await query(heightSql);

                                let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                let annualIncomeResult = await query(annualIncomeSql);

                                let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                let employmentTypeResult = await query(employmentTypeSql);

                                userResult[0].masterEntryData = {
                                    "occupation": occupationResult,
                                    "education": educationResult,
                                    "maritalStatus": maritalStatusResult,
                                    "religion": religionResult,
                                    "community": communityResult,
                                    "subCommunity": subCommunityResult,
                                    "diet": dietResult,
                                    "height": heightResult,
                                    "annualIncome": annualIncomeResult,
                                    "employmentType": employmentTypeResult,
                                    "maxAge": maxAge[0].maxAge,
                                    "minAge": minAge[0].minAge,
                                    "ageList": ageList,
                                    "cityName": cityName
                                }

                                await commit();
                                let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                return res.status(200).send(successResult);
                            } else {
                                await rollback();
                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                next(errorResult);
                            }
                        } else {
                            return res.status(401).json({
                                message: 'Unable to Sign JWT',
                                error: signJWTResult.error
                            });
                        }
                    }


                } else {
                    let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                    next(errorResult);
                }
            } else {
                await rollback();
                let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
                next(errorResult);
            }
        } else {
            let requiredFields = ['email', 'password'];
            let validationResult = header.validateRequiredFields(req, requiredFields);
            if (validationResult && validationResult.statusCode == 200) {
                let authorizationResult = await header.validateAuthorization(req, res, next);
                if (authorizationResult.statusCode == 200) {
                    let userDevice = authorizationResult.currentUserDevice;
                    let deviceDetailResult;
                    let appId: number;
                    if (userDevice.app == 'MatrimonyAdmin') {
                        appId = 1;
                    } else if (userDevice.app == 'MatrimonyAndroid') {
                        appId = 2;
                    } else {
                        appId = 3;
                    }
                    await beginTransaction();
                    let userId: number;
                    let insertRefTokenResult;

                    let sql = `SELECT u.*, ur.roleId, img.imageUrl FROM users u
                        LEFT JOIN userroles ur ON ur.userId = u.id
                        LEFT JOIN images img ON img.id =u.imageId
                        WHERE u.email = '` + req.body.email + `' AND u.isActive = true AND ur.roleId = 2`;
                    let result = await query(sql);
                    let userPerDetailSql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName as cityName, addr.stateName as stateName, addr.countryName as countryName, em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                        FROM users u
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
                         WHERE ur.roleId = 2 AND u.email =  '` + req.body.email + `' `;
                    let userResult = await query(userPerDetailSql);
                    if (result && result.length > 0) {
                        if (result[0].isDisable) {
                            let errorResult = new ResultError(400, true, "users.login() Error", new Error('Your profile was block by Admin. You cannot login.'), '');
                            next(errorResult);
                        } else {
                            userId = result[0].id;
                            if (result && result.length > 0) {
                                bcryptjs.compare(req.body.password, result[0].password, async (error, hashresult: any) => {
                                    if (hashresult == false) {
                                        return res.status(401).json({
                                            message: 'Password Mismatch'
                                        });
                                    } else if (hashresult) {
                                        let signJWTResult: any = await signJWT(result[0]);
                                        if (signJWTResult && signJWTResult.token) {
                                            userResult[0].token = signJWTResult.token;
                                            if (userDevice) {
                                                let checkDeviceSql = `SELECT * FROM userdevicedetail WHERE userId = ` + userId + ``;
                                                result = await query(checkDeviceSql);
                                                userDevice.apiCallTime = userDevice.apiCallTime ? userDevice.apiCallTime : '';
                                                if (result && result.length > 0) {
                                                    let updateDetailSql = `UPDATE userdevicedetail SET userId = ` + userId + `,applicationId = ` + appId + `,deviceId = '` + userDevice.deviceId + `',fcmToken = '` + userDevice.fcmToken + `',deviceLocation = '` + userDevice.deviceLocation + `',deviceManufacturer = '` + userDevice.deviceManufacturer + `',deviceModel = '` + userDevice.deviceModel + `',apiCallTime = '` + userDevice.apiCallTime + `' WHERE userId = ` + userId;
                                                    result = await query(updateDetailSql);
                                                } else {
                                                    let insertDetailSql = `INSERT INTO userdevicedetail(userId, applicationId, deviceId, fcmToken, deviceLocation, deviceManufacturer, deviceModel, apiCallTime) VALUES(` + userId + `,` + appId + `,'` + userDevice.deviceId + `','` + userDevice.fcmToken + `','` + userDevice.deviceLocation + `','` + userDevice.deviceManufacturer + `','` + userDevice.deviceModel + `','` + userDevice.apiCallTime + `')`;
                                                    result = await query(insertDetailSql);
                                                }
                                            }
                                            let refreshToken = await createRefreshToken(userResult[0]);
                                            //insert refresh token
                                            let insertRefreshTokenSql = `INSERT INTO userrefreshtoken(userId, refreshToken, expireAt) VALUES(?,?,?)`;
                                            insertRefTokenResult = await query(insertRefreshTokenSql, [userResult[0].id, refreshToken.token, refreshToken.expireAt]);
                                            if (insertRefTokenResult && insertRefTokenResult.affectedRows > 0) {
                                                userResult[0].refreshToken = refreshToken.token;

                                                let userflagvalues = `SELECT ufv.*, uf.flagName, uf.displayName FROM userflagvalues ufv
                                                LEFT JOIN userflags uf ON uf.id = ufv.userFlagId
                                                WHERE ufv.userId = ` + userId + ``;
                                                userResult[0].userFlags = await query(userflagvalues);

                                                let todayDate = new Date();
                                                let date = new Date(todayDate).getFullYear() + "-" + ("0" + (new Date(todayDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(todayDate).getDate()).slice(-2) + "";

                                                let userPackages = `SELECT up.*, p.name as packageName, td.id as timeDurationId, td.value FROM userpackage up
                                                    LEFT JOIN package p ON p.id = up.packageId
                                                    LEFT JOIN packageduration pd ON pd.id = up.packageDurationId
                                                    LEFT JOIN timeduration td ON td.id = pd.timeDurationId
                                                        WHERE up.userId = ` + userId + ` order by createdDate DESC`;
                                                let userPackage = await query(userPackages);
                                                if (userPackage && userPackage.length > 0) {
                                                    for (let k = 0; k < userPackage.length; k++) {
                                                        let packageFacility = await query(`SELECT pf.*, pff.name FROM packagefacility pf
                                                            LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                                                             WHERE pf.packageId = ` + userPackage[k].packageId);
                                                        userPackage[k].packageFacility = packageFacility;
                                                    }
                                                }
                                                userResult[0].userPackage = userPackage[0];

                                                let minAge = await query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                                FROM users u
                                                LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                LEFT JOIN userroles ur ON ur.userId = u.id
                                                WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);
                                                let maxAge = await query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                                FROM users u
                                                LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                                LEFT JOIN userroles ur ON ur.userId = u.id
                                                WHERE ur.roleId = 2 AND u.id != ` + userResult[0].id + ` AND (upa.userId = u.id) AND u.id NOT IN (select userBlockId from userblock where userId = ` + userResult[0].id + `)`);

                                                let ageList = [];
                                                for (let i = 18; i <= 60; i++) {
                                                    ageList.push(i)
                                                }
                                                console.log(ageList)

                                                let cityName = await query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)

                                                let occupationSql = `SELECT * FROM occupation WHERE isActive = 1 AND isDelete = 0`;
                                                let occupationResult = await query(occupationSql);

                                                let educationSql = `SELECT * FROM education WHERE isActive = 1 AND isDelete = 0`;
                                                let educationResult = await query(educationSql);

                                                let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1 AND isDelete = 0`;
                                                let maritalStatusResult = await query(maritalStatusSql);

                                                let religionSql = `SELECT * FROM religion WHERE isActive = 1 AND isDelete = 0`;
                                                let religionResult = await query(religionSql);

                                                let communitySql = `SELECT * FROM community WHERE isActive = 1 AND isDelete = 0`;
                                                let communityResult = await query(communitySql);

                                                let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1 AND isDelete = 0`;
                                                let subCommunityResult = await query(subCommunitySql);

                                                let dietSql = `SELECT * FROM diet WHERE isActive = 1 AND isDelete = 0`;
                                                let dietResult = await query(dietSql);

                                                let heightSql = `SELECT * FROM height WHERE isActive = 1 AND isDelete = 0 order by name`;
                                                let heightResult = await query(heightSql);

                                                let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1 AND isDelete = 0`;
                                                let annualIncomeResult = await query(annualIncomeSql);

                                                let employmentTypeSql = `SELECT * FROM employmenttype WHERE isActive = 1 AND isDelete = 0`;
                                                let employmentTypeResult = await query(employmentTypeSql);

                                                userResult[0].masterEntryData = {
                                                    "occupation": occupationResult,
                                                    "education": educationResult,
                                                    "maritalStatus": maritalStatusResult,
                                                    "religion": religionResult,
                                                    "community": communityResult,
                                                    "subCommunity": subCommunityResult,
                                                    "diet": dietResult,
                                                    "height": heightResult,
                                                    "annualIncome": annualIncomeResult,
                                                    "employmentType": employmentTypeResult,
                                                    "maxAge": maxAge[0].maxAge,
                                                    "minAge": minAge[0].minAge,
                                                    "ageList": ageList,
                                                    "cityName": cityName
                                                }

                                                await commit();
                                                let successResult = new ResultSuccess(200, true, 'Login User', userResult, 1, "");
                                                return res.status(200).send(successResult);
                                            } else {
                                                await rollback();
                                                let errorResult = new ResultError(400, true, "users.signUp() Error", new Error('Error While Login'), '');
                                                next(errorResult);
                                            }
                                        } else {
                                            return res.status(401).json({
                                                message: 'Unable to Sign JWT',
                                                error: signJWTResult.error
                                            });
                                        }
                                    }
                                });
                            } else {
                                await rollback();
                                let errorResult = new ResultError(400, true, "users.login() Error", new Error('Error While Login'), '');
                                next(errorResult);
                            }
                        }
                    } else {
                        let successResult = new ResultSuccess(200, true, 'Email is incorrect!', [], 1, "");
                        return res.status(200).send(successResult);
                    }

                } else {
                    let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                    next(errorResult);
                }
            } else {
                await rollback();
                let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
                next(errorResult);
            }
        }
    } catch (error: any) {
        await rollback();
        let errorResult = new ResultError(500, true, 'Users.login() Exception', error, '');
        next(errorResult);
    }
};

const getMasterData = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Get Master Data');
        let result: any;
        let sql = "CALL getMasterData()";
        let masterData = await query(sql);
        if (masterData && masterData.length > 0) {
            let minAge = await query(`SELECT min(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as minAge
                                            FROM users u
                                            LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            LEFT JOIN userroles ur ON ur.userId = u.id
                                            WHERE ur.roleId = 2 `);
            let maxAge = await query(`SELECT max(DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0) as maxAge
                                            FROM users u
                                            LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
                                            LEFT JOIN userroles ur ON ur.userId = u.id
                                            WHERE ur.roleId = 2`);
            let ageList = [];
            for (let i = 18; i <= 60; i++) {
                ageList.push(i)
            }
            let cityName = await query(`select (cityName) FROM addresses where cityName is not null or cityName !='' group by cityName  having  cityName !=''`)
            result = {
                "occupation": masterData[0],
                "education": masterData[1],
                "maritalStatus": masterData[2],
                "religion": masterData[3],
                "community": masterData[4],
                "subCommunity": masterData[5],
                "diet": masterData[6],
                "height": masterData[7],
                "annualIncome": masterData[8],
                "employmentType": masterData[9],
                "maxAge": maxAge[0].maxAge,
                "minAge": minAge[0].minAge,
                "ageList": ageList,
                "cityName": cityName
            }
            let successResult = new ResultSuccess(200, true, 'Get Master Data Successfully', result, masterData.length, '');
            return res.status(200).send(successResult);
        } else {
            let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.getUsers() Exception', error, '');
        next(errorResult);
    }
}

const getAllUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Users');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let sql = `SELECT  u.id, u.firstName, u.middleName, u.lastName, u.gender, u.contactNo, u.email, img.imageUrl ,
                u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
                u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
                 FROM users u
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id = u.imageId
                WHERE u.isDelete = 0 ANd ur.roleId = 2 AND u.id != ` + userId + ` AND
                u.id NOT IN (select userBlockId from userblock where userId = ` + userId + `) AND
                u.id NOT IN (select userId from userblock where userBlockId = ` + userId + `)
                AND u.isDisable = 0
                 group by u.id`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result && result.length > 0) {
                let successResult = new ResultSuccess(200, true, 'Get Users Successfully', result, result.length, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'users.getUsers() Exception', error, '');
        next(errorResult);
    }
};

const viewUserDetail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting User Detail');
        let requiredFields = ['id'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let sql = `SELECT u.id,udd.fcmToken, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, upd.companyName, upd.businessName, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName as cityName, addr.stateName as stateName, addr.countryName as countryName, em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age, u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite, u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed
                FROM users u
                LEFT JOIN userroles ur ON ur.userId = u.id
                LEFT JOIN images img ON img.id = u.imageId
                LEFT JOIN userpersonaldetail upd ON upd.userId = u.id
                LEFT JOIN userdevicedetail udd ON udd.userId = u.id
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
                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId

                 WHERE ur.roleId = 2 AND u.id = ` + req.body.id;
                let result = await query(sql);
                if (result && result.length > 0) {
                    sql = `SELECT up.packageId,p.name as packageName,up.packageDurationId,up.startDate,up.endDate,up.netAmount,pay.paymentMode
                    ,t.value   FROM  userpackage up
                    LEFT JOIN package p on p.id= up.packageId
                    LEFT join payment pay on pay.id= up.paymentId
                    left join packageduration pd on pd.packageId = up.packageId
                    left join timeduration t on t.id = pd.timeDurationId
                    WHERE up.userId = `+ req.body.id + ` order by up.createdDate desc;`
                    let userPackage = await query(sql);
                    let packages = userPackage[0]
                    // result[0].packages = packages
                    // console.log(result[0].packages )
                    if (packages) {
                        let packageFacility = await query(`SELECT  pff.name  FROM packagefacility pf
                            LEFT JOIN premiumfacility pff ON pff.id = pf.premiumFacilityId
                             WHERE pf.packageId = ` + packages.packageId);
                        packages.packageFacility = packageFacility;

                        result[0].userPackage = packages
                    }
                    if (authorizationResult.token == '') {
                        let authorizationHeader = req.headers['authorization'];
                        let token: any = authorizationHeader?.split(' ')[1];
                        authorizationResult.token = token;
                    }
                    let successResult = new ResultSuccess(200, true, 'Get Users Detail Successfully', result, result.length, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let errorResult = new ResultError(400, true, 'Data Not Available', new Error('Data Not Available'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.getUserDetail() Exception', error, '');
        next(errorResult);
    }
};

const updateUserProfilePic = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Updating Users');
        let requiredFields = ['id', 'image'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let result;
                let imageId;
                req.body.userId = req.body.id;
                try {
                    let checkSql = `SELECT * FROM users WHERE id = ` + req.body.userId;
                    let checkResult = await query(checkSql);
                    if (checkResult && checkResult.length) {
                        let oldImageId = checkResult[0].imageId;
                        if (oldImageId) {
                            if (req.body.image && req.body.image.indexOf('content') == -1) {
                                let sql = `INSERT INTO images(createdBy, modifiedBy) VALUES (` + req.body.userId + `,` + req.body.userId + `)`;
                                result = await query(sql);
                                if (result.affectedRows > 0) {
                                    imageId = result.insertId;

                                    let image = req.body.image;
                                    let data = image.split(',');
                                    if (data && data.length > 1) {
                                        image = image.split(',')[1]
                                    }

                                    let dir = './content';
                                    if (!fs.existsSync(dir)) {
                                        fs.mkdirSync(dir);
                                    }

                                    let dir1 = './content/user';
                                    if (!fs.existsSync(dir1)) {
                                        fs.mkdirSync(dir1);
                                    }

                                    let dir2 = './content/user/' + req.body.userId;
                                    if (!fs.existsSync(dir2)) {
                                        fs.mkdirSync(dir2);
                                    }
                                    const fileContentsUser = new Buffer(image, 'base64')
                                    let imgPath = "./content/user/" + req.body.userId + "/" + imageId + "-realImg.jpeg";

                                    fs.writeFileSync(imgPath, fileContentsUser, (err: any) => {
                                        if (err)
                                            return console.error(err)
                                        console.log('file saved imagePath')
                                    });
                                    let imagePath = "./content/user/" + req.body.userId + "/" + imageId + ".jpeg";
                                    sharp(imgPath).resize({
                                        height: 100,
                                        width: 100
                                    }).toFile(imagePath)
                                        .then(function (newFileInfo: any) {
                                            console.log(newFileInfo);
                                        });
                                    let updateimagePathSql = `UPDATE images SET imageUrl='` + imagePath.substring(2) + `' WHERE id=` + imageId;
                                    let updateimagePathResult = await query(updateimagePathSql);
                                    if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {
                                        let addUserImageId = `UPDATE users SET imageId = ` + imageId + ` WHERE id = ` + req.body.userId;
                                        result = await query(addUserImageId);
                                        if (result && result.affectedRows > 0) {
                                            let delSql = `DELETE FROM images where Id = ` + oldImageId;
                                            let delResult = await query(delSql);
                                            if (delResult && delResult.affectedRows > 0) {
                                                let userSql = `SELECT u.*, img.imageUrl FROM users u
                                                LEFT JOIN images img ON img.id = u.imageId
                                                WHERE u.id = ` + req.body.userId;
                                                let userResult = await query(userSql);
                                                if (userResult && userResult.length > 0) {
                                                    let successResult = new ResultSuccess(200, true, 'Update User Profile Pic', userResult, userResult.length, authorizationResult.token);
                                                    return res.status(200).send(successResult);
                                                } else {
                                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                                    next(errorResult);
                                                }
                                            }
                                        }
                                    } else {
                                        let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                    next(errorResult);
                                }
                            } else {
                                let addUserImageId = `UPDATE users SET imageId = ` + oldImageId + ` WHERE id = ` + req.body.userId;
                                result = await query(addUserImageId);
                                let userSql = `SELECT u.*, img.imageUrl FROM users u
                                            LEFT JOIN images img ON img.id = u.imageId
                                            WHERE u.id = ` + req.body.userId;
                                let userResult = await query(userSql);
                                if (userResult && userResult.length > 0) {
                                    let successResult = new ResultSuccess(200, true, 'Update User Profile Pic', userResult, userResult.length, authorizationResult.token);
                                    return res.status(200).send(successResult);
                                } else {
                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Data'), '');
                                    next(errorResult);
                                }
                            }
                        } else {
                            if (req.body.image && req.body.image.indexOf('content') == -1) {
                                let sql = `INSERT INTO images(createdBy, modifiedBy) VALUES (` + req.body.userId + `,` + req.body.userId + `)`;
                                result = await query(sql);
                                if (result.affectedRows > 0) {
                                    imageId = result.insertId;

                                    let image = req.body.image;
                                    let data = image.split(',');
                                    if (data && data.length > 1) {
                                        image = image.split(',')[1]
                                    }

                                    let dir = './content';
                                    if (!fs.existsSync(dir)) {
                                        fs.mkdirSync(dir);
                                    }

                                    let dir1 = './content/user';
                                    if (!fs.existsSync(dir1)) {
                                        fs.mkdirSync(dir1);
                                    }

                                    let dir2 = './content/user/' + req.body.userId;
                                    if (!fs.existsSync(dir2)) {
                                        fs.mkdirSync(dir2);
                                    }
                                    const fileContentsUser = new Buffer(image, 'base64')
                                    let imgPath = "./content/user/" + req.body.userId + "/" + imageId + "-realImg.jpeg";

                                    fs.writeFileSync(imgPath, fileContentsUser, (err: any) => {
                                        if (err)
                                            return console.error(err)
                                        console.log('file saved imagePath')
                                    });
                                    let imagePath = "./content/user/" + req.body.userId + "/" + imageId + ".jpeg";
                                    sharp(imgPath).resize({
                                        height: 100,
                                        width: 100
                                    }).toFile(imagePath)
                                        .then(function (newFileInfo: any) {
                                            console.log(newFileInfo);
                                        });
                                    let updateimagePathSql = `UPDATE images SET imageUrl='` + imagePath.substring(2) + `' WHERE id=` + imageId;
                                    let updateimagePathResult = await query(updateimagePathSql);
                                    if (updateimagePathResult && updateimagePathResult.affectedRows > 0) {
                                        let addUserImageId = `UPDATE users SET imageId = ` + imageId + ` WHERE id = ` + req.body.userId;
                                        result = await query(addUserImageId);
                                        let userSql = `SELECT u.*, img.imageUrl FROM users u
                                        LEFT JOIN images img ON img.id = u.imageId
                                        WHERE u.id = ` + req.body.userId;
                                        let userResult = await query(userSql);
                                        if (userResult && userResult.length > 0) {
                                            let successResult = new ResultSuccess(200, true, 'Update User Profile Pic', userResult, userResult.length, authorizationResult.token);
                                            return res.status(200).send(successResult);
                                        } else {
                                            let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                            next(errorResult);
                                        }
                                    } else {
                                        let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                        next(errorResult);
                                    }
                                } else {
                                    let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Error While Updating Profile Pic'), '');
                                    next(errorResult);
                                }
                            } else {
                                let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('Image Not Found'), '');
                                next(errorResult);
                            }
                        }
                    } else {
                        let errorResult = new ResultError(400, true, "users.updateUserProfilePic() Error", new Error('User Not Found'), '');
                        next(errorResult);
                    }
                } catch (err) {
                    let imagePath = "./content/user/" + req.body.userId + "/" + imageId + ".jpeg";
                    if (fs.existsSync(imagePath)) {
                        fs.unlink(imagePath, (err: any) => {
                            if (err) throw err;
                            console.log(imagePath + ' was deleted');
                        });
                    }
                    let dir = './content/user/' + req.body.userId;
                    if (fs.existsSync(dir)) {
                        fs.rmdir(dir, (err: any) => {
                            if (err) throw err;
                            console.log(dir + ' was deleted');
                        });
                    }
                    result = err;
                }
                return result;
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.updateUserProfilePic() Exception', error, '');
        next(errorResult);
    }
};

const updateUserProfileDetail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Updating Users');
        let requiredFields = ['id', 'firstName', 'lastName', 'email', 'gender', 'birthDate', 'addressLine1', 'pincode', 'religionId', 'communityId', 'maritalStatusId', 'occupationId', 'educationId', 'annualIncomeId', 'heightId', 'languages', 'employmentTypeId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                await beginTransaction();
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                req.body.contactNo = req.body.contactNo ? req.body.contactNo : '';
                req.body.middleName = req.body.middleName ? req.body.middleName : '';
                req.body.countryName = req.body.countryName ? req.body.countryName : '';
                req.body.stateName = req.body.stateName ? req.body.stateName : '';
                req.body.cityName = req.body.cityName ? req.body.cityName : '';
                req.body.aboutMe = req.body.aboutMe ? req.body.aboutMe : '';
                req.body.expectation = req.body.expectation ? req.body.expectation : '';
                req.body.eyeColor = req.body.eyeColor ? req.body.eyeColor : '';
                let birthDate = req.body.birthDate ? new Date(req.body.birthDate) : '';
                let bDate = new Date(birthDate).getFullYear().toString() + '-' + ("0" + (new Date(birthDate).getMonth() + 1)).slice(-2) + '-' + ("0" + new Date(birthDate).getDate()).slice(-2) + ' ' + ("0" + (new Date(birthDate).getHours())).slice(-2) + ':' + ("0" + (new Date(birthDate).getMinutes())).slice(-2) + ':' + ("0" + (new Date(birthDate).getSeconds())).slice(-2);

                let result;
                let sql = `UPDATE users SET firstName = '` + req.body.firstName + `',middleName = '` + req.body.middleName + `',lastName = '` + req.body.lastName + `',contactNo = '` + req.body.contactNo + `',email = '` + req.body.email + `',gender = '` + req.body.gender + `' WHERE id = ` + req.body.id + ``;
                result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let userPerDetailSql = `SELECT * FROM userpersonaldetail WHERE userId = ` + req.body.id + ``;
                    result = await query(userPerDetailSql);
                    if (result && result.length > 0) {
                        let userpersonaldetailId = result[0].id;
                        req.body.addressId = result[0].addressId;
                        req.body.birthDate = req.body.birthDate ? req.body.birthDate : '';
                        let updateAddSql = `UPDATE addresses SET addressLine1 = '` + req.body.addressLine1 + `', addressLine2 = '` + req.body.addressLine2 + `', pincode = '` + req.body.pincode + `', cityId = null ,stateId = null, countryId = null, countryName = '` + req.body.countryName + `', stateName = '` + req.body.stateName + `', cityName = '` + req.body.cityName + `' WHERE id = ` + req.body.addressId + ``;
                        let updateAddressResult = await query(updateAddSql);
                        if (updateAddressResult && updateAddressResult.affectedRows > 0) {
                            // let addressId = updateAddressResult[0].id;
                            let updateSql = `UPDATE userpersonaldetail SET addressId = ` + req.body.addressId + `, religionId = ` + req.body.religionId + `,communityId = ` + req.body.communityId + `,maritalStatusId = ` + req.body.maritalStatusId + `,occupationId = ` + req.body.occupationId + `,educationId = ` + req.body.educationId + `,subCommunityId = ` + req.body.subCommunityId + `,dietId = ` + req.body.dietId + `,annualIncomeId = ` + req.body.annualIncomeId + `,heightId = ` + req.body.heightId + `,birthDate = '` + bDate + `',languages = '` + req.body.languages + `',eyeColor = '` + req.body.eyeColor + `', businessName = '` + req.body.businessName + `', companyName = '` + req.body.companyName + `', employmentTypeId = ` + req.body.employmentTypeId + `, expectation = '` + req.body.expectation + `', aboutMe = '` + req.body.aboutMe + `'  WHERE id = ` + userpersonaldetailId + ``;
                            result = await query(updateSql);
                            if (result && result.affectedRows > 0) {
                                let sql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName, addr.stateName AS state,addr.countryName AS country, em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                FROM users u
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
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                 WHERE ur.roleId = 2 AND u.id = ` + req.body.id;
                                let result = await query(sql);
                                await commit();
                                let successResult = new ResultSuccess(200, true, 'Update User Personal Detail', result, 1, authorizationResult.token);
                                return res.status(200).send(successResult);
                            } else {
                                await rollback();
                                let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
                                next(errorResult);
                            }
                        } else {
                            await rollback();
                            let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
                            next(errorResult);
                        }
                    } else {
                        let insertAddress = `INSERT INTO addresses(addressLine1, addressLine2, pincode,cityId, stateId, countryId, countryName, stateName, cityName, createdBy, modifiedBy) VALUES('` + req.body.addressLine1 + `','` + req.body.addressLine2 + `','` + req.body.pincode + `',null,null,null,'` + req.body.countryName + `','` + req.body.stateName + `','` + req.body.cityName + `',` + userId + `,` + userId + `)`;
                        let addressResult = await query(insertAddress);
                        if (addressResult && addressResult.insertId > 0) {
                            req.body.addressId = addressResult.insertId;
                            let insertSql = `INSERT INTO userpersonaldetail(userId, addressId, religionId, communityId, maritalStatusId, occupationId, educationId, subCommunityId, dietId, annualIncomeId, heightId, birthDate, languages, eyeColor, businessName, companyName, employmentTypeId, expectation, aboutMe, createdBy, modifiedBy) VALUES(` + req.body.id + `,` + req.body.addressId + `,` + req.body.religionId + `,` + req.body.communityId + `,` + req.body.maritalStatusId + `,` + req.body.occupationId + `,` + req.body.educationId + `,` + req.body.subCommunityId + `,` + req.body.dietId + `,` + req.body.annualIncomeId + `,` + req.body.heightId + `,'` + bDate + `','` + req.body.languages + `','` + req.body.eyeColor + `', '` + req.body.businessName + `', '` + req.body.companyName + `', ` + req.body.employmentTypeId + `, '` + req.body.expectation + `', '` + req.body.aboutMe + `',` + userId + `,` + userId + `)`;
                            result = await query(insertSql);
                            if (result && result.affectedRows > 0) {
                                let sql = `SELECT u.id, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, upd.birthDate, upd.languages, upd.eyeColor, upd.expectation, upd.aboutMe, img.imageUrl, r.name as religion, ms.name as maritalStatus, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName, addr.stateName AS state,addr.countryName AS country, em.name as employmentType, DATE_FORMAT(FROM_DAYS(DATEDIFF(now(),upd.birthDate)), '%Y')+0 AS age
                                FROM users u
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
                                LEFT JOIN employmenttype em ON em.id = upd.employmenttypeId
                                 WHERE ur.roleId = 2 AND u.id = ` + req.body.id;
                                let result = await query(sql);
                                await commit();
                                let successResult = new ResultSuccess(200, true, 'Insert User Personal Detail', result, 1, authorizationResult.token);
                                return res.status(200).send(successResult);
                            } else {
                                await rollback();
                                let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                                next(errorResult);
                            }
                        } else {
                            await rollback();
                            let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Inserting Data'), '');
                            next(errorResult);
                        }
                    }
                } else {
                    await rollback();
                    let errorResult = new ResultError(400, true, "users.updateUserProfileDetail() Error", new Error('Error While Updating Data'), '');
                    next(errorResult);
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
        let errorResult = new ResultError(500, true, 'users.updateUserProfileDetail() Exception', error, '');
        next(errorResult);
    }
};

const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Reset Password');
        let requiredFields = ['email'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            await beginTransaction();
            let result: any;
            let sql = `SELECT * FROM users WHERE email = '` + req.body.email + `'`;
            let userData = await query(sql);
            if (userData && userData.length > 0) {
                let token = crypto.randomBytes(48).toString('hex');
                let expireAtDate = new Date(new Date().toUTCString());
                expireAtDate.setDate(expireAtDate.getDate() + 1);
                let data = {
                    userId: userData[0].id,
                    token: token,
                    isUsed: 0,
                    expireAt: expireAtDate,
                    isActive: true,
                    isDelete: false,
                    createdDate: new Date(new Date().toUTCString()),
                    modifiedDate: new Date(new Date().toUTCString())
                }
                let sql = "INSERT INTO usertokens SET ?";
                result = await query(sql, data);
                if (result.insertId > 0) {
                    let resultEmail = await sendEmail(config.emailMatrimonySetPassword.fromName + ' <' + config.emailMatrimonySetPassword.fromEmail + '>', userData[0].email, config.emailMatrimonySetPassword.subject, "", config.emailMatrimonySetPassword.html.replace("[VERIFICATION_TOKEN]", token).replace("[NAME]", (userData[0].firstName + ' ' + userData[0].lastName)), null, null);
                    await commit();
                    console.log(userData[0].firstName)
                    console.log(userData[0].lastName)
                    result = resultEmail;
                    let successResult = new ResultSuccess(200, true, 'Send mail successfully!', result, 1, "");
                    return res.status(200).send(successResult);
                } else {
                    await rollback();
                    result.length = 0;
                }
            } else {
                await rollback();
                let errorResult = new ResultError(400, true, 'User not found', new Error('Data Not Available'), '');
                next(errorResult);
            }
        } else {
            await rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await rollback();
        let errorResult = new ResultError(500, true, 'users.resetPassword() Exception', error, '');
        next(errorResult);
    }
};

const sendEmail = async (from: string, to: string, subject: string, text: string, html: any, fileName: any, invoicePdf: any) => {
    let result;
    try {
        // create reusable transporter object using the default SMTP transport
        let systemFlags = `SELECT * FROM systemflags where flagGroupId = 2`;
        let _systemFlags = await query(systemFlags);
        let _host;
        let _port;
        let _secure;
        let _user;
        let _password;

        for (let i = 0; i < _systemFlags.length; i++) {
            if (_systemFlags[i].id == 4) {
                _host = _systemFlags[i].value;
            } else if (_systemFlags[i].id == 5) {
                _port = parseInt(_systemFlags[i].value);
            } else if (_systemFlags[i].id == 6) {
                if (_systemFlags[i].value == '1') {
                    _secure = true;
                } else {
                    _secure = false;
                }
            } else if (_systemFlags[i].id == 1) {
                _user = _systemFlags[i].value;
            } else if (_systemFlags[i].id == 2) {
                _password = _systemFlags[i].value;
            }
        }
        // create reusable transporter object using the default SMTP transport
        let transporter = nodemailer.createTransport({
            host: _host,
            port: _port,
            secure: _secure, // true for 465, false for other ports
            auth: {
                user: _user,
                pass: _password
            }
        });
        // setup email data with unicode symbols
        let mailOptions = {
            from: _user,
            to: to,
            subject: subject,
            html: html
        };

        // send mail with defined transport object
        result = await transporter.sendMail(mailOptions);

        // console.log("Message sent: %s", result);
    } catch (error) {
        result = error;
    }
    return result;
};

const verifyforgotPasswordLink = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Verify Forgot Password Link');
        let requiredFields = ['token'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let result;
            let sql = `SELECT * FROM usertokens WHERE isDelete = 0 AND isUsed = 0  AND token = '` + req.body.token + `'`;
            result = await query(sql);
            if (result && result.length > 0) {
                let expireDate = new Date(result[0].expireAt);
                let currentDate = new Date(new Date().toUTCString());
                let exTime = expireDate.getTime();
                let curTime = currentDate.getTime();
                if (exTime > curTime) {
                    let successResult = new ResultSuccess(200, true, 'Token is valid!', result, 1, "null");
                    return res.status(200).send(successResult);
                } else {
                    let successResult = 'Token is expired!'
                    return res.status(200).send(successResult);
                }
            } else {
                let successResult = 'You have already used this token';
                return res.status(200).send(successResult);
            }
        } else {
            await rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.verifyforgotPasswordLink() Exception', error, '');
        next(errorResult);
    }
};

const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Reset Password');
        let requiredFields = ['id', 'password', 'token'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            bcryptjs.hash(req.body.password, 10, async (hashError, hash) => {
                if (hashError) {
                    return res.status(401).json({
                        message: hashError.message,
                        error: hashError
                    });
                }
                let sql = `UPDATE users SET password = '` + hash + `' where id = ` + req.body.id + ``;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    if (req.body.token) {
                        let userTokenUpdateSql = `UPDATE usertokens SET isUsed = 1 WHERE token = '` + req.body.token + `' AND userId = ` + req.body.id + ``;
                        result = await query(userTokenUpdateSql);
                    }
                    let successResult = new ResultSuccess(200, true, 'Password reset successfully!', result, 1, "null");
                    return res.status(200).send(successResult);
                }
                else {
                    await rollback();
                    let errorResult = new ResultError(400, true, "users.resetPassword() Error", new Error('Error While Reset Password'), '');
                    next(errorResult);
                }
            });
        } else {
            await rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        await rollback();
        let errorResult = new ResultError(500, true, 'users.resetPassword() Exception', error, '');
        next(errorResult);
    }
};

const changePassword = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Change Password');
        let requiredFields = ['oldPassword', 'newPassword'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let sql = `SELECT * FROM users WHERE id = ` + userId;
                result = await query(sql);
                if (result && result.length > 0) {
                    bcryptjs.compare(req.body.oldPassword, result[0].password, async (error, hashresult: any) => {
                        if (hashresult == false) {
                            return res.status(401).json({
                                message: 'Your old password is not match'
                            });
                        } else if (hashresult) {
                            bcryptjs.hash(req.body.newPassword, 10, async (hashError, hash) => {
                                if (hashError) {
                                    return res.status(401).json({
                                        message: hashError.message,
                                        error: hashError
                                    });
                                }
                                let sql = `UPDATE users SET password = '` + hash + `' where id = ` + userId + ``;
                                let result = await query(sql);
                                if (result && result.affectedRows > 0) {
                                    let successResult = new ResultSuccess(200, true, 'Password Change successfully!', result, 1, "null");
                                    return res.status(200).send(successResult);
                                } else {
                                    await rollback();
                                    let errorResult = new ResultError(400, true, "users.changePassword() Error", new Error('Error While Change Password'), '');
                                    next(errorResult);
                                }
                            });
                        }
                    });
                } else {
                    let errorResult = "User Not Found";
                    next(errorResult);
                }
            } else {
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
        let errorResult = new ResultError(500, true, 'users.changePassword() Exception', error, '');
        next(errorResult);
    }
};

const changeContact = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Change Contact');
        let requiredFields = ['oldContact', 'newContact'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let searchSql = `SELECT * FROM users WHERE contactNo = '` + req.body.oldContact + `' AND id = ` + userId;
                let searchResult = await query(searchSql);
                if (searchResult && searchResult.length > 0) {
                    let checkSql = `SELECT * FROM users WHERE contactNo = '` + req.body.newContact + `' AND id != ` + userId + ``;
                    result = await query(checkSql);
                    if (result && result.length > 0) {
                        let errorResult = "ContactNo Already Exist";
                        next(errorResult);
                    } else {
                        let sql = `UPDATE users SET contactNo = '` + req.body.newContact + `' where id = ` + userId + ``;
                        result = await query(sql);
                        if (result && result.affectedRows > 0) {
                            let successResult = new ResultSuccess(200, true, 'Contact Change successfully!', result, 1, "null");
                            return res.status(200).send(successResult);
                        } else {
                            await rollback();
                            let errorResult = new ResultError(400, true, "users.changeContact() Error", new Error('Error While Change Contact'), '');
                            next(errorResult);
                        }
                    }
                } else {
                    let errorResult = "User Not Found";
                    next(errorResult);
                }
            } else {
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
        let errorResult = new ResultError(500, true, 'users.changeContact() Exception', error, '');
        next(errorResult);
    }
};

const changeEmail = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Reset Password');
        let requiredFields = ['oldEmail', 'newEmail'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let result;
                let searchSql = `SELECT * FROM users WHERE email = '` + req.body.oldEmail + `' AND id = ` + userId;
                let searchResult = await query(searchSql);
                if (searchResult && searchResult.length > 0) {
                    let checkSql = `SELECT * FROM users WHERE email = '` + req.body.newEmail + `' AND id != ` + userId + ``;
                    result = await query(checkSql);
                    if (result && result.length > 0) {
                        let errorResult = new ResultError(400, true, "users.changeEmail() Error", new Error('Email Already exists'), '');
                        next(errorResult);
                    } else {
                        let sql = `UPDATE users SET email = '` + req.body.newEmail + `' where id = ` + userId + ``;
                        result = await query(sql);
                        if (result && result.affectedRows > 0) {
                            let successResult = new ResultSuccess(200, true, 'Email Change successfully!', result, 1, "null");
                            return res.status(200).send(successResult);
                        } else {
                            await rollback();
                            let errorResult = new ResultError(400, true, "users.changeEmail() Error", new Error('Error While Change Password'), '');
                            next(errorResult);
                        }
                    }
                } else {
                    let errorResult = "User Not Found";
                    next(errorResult);
                }
            } else {
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
        let errorResult = new ResultError(500, true, 'users.changeEmail() Exception', error, '');
        next(errorResult);
    }
};

const searchUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Application User');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let sql = `SELECT u.id, upa.userId, img.imageUrl, u.firstName, u.middleName, u.lastName, u.contactNo, u.email, u.gender, upa.birthDate, DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0 AS age, upa.eyeColor, upa.languages, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName, addr.stateName AS state,addr.stateName AS country, ms.name as maritalStatus, r.name as religion, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height , u.id IN (select proposalUserId from userproposals where userId = ` + userId + `) as isProposed,
            u.id IN (select favUserId from userfavourites where userId = ` + userId + `) as isFavourite
            FROM users u
            LEFT JOIN userpersonaldetail upa ON upa.userId = u.id
            LEFT JOIN userroles ur ON ur.userId = u.id
            LEFT JOIN images img ON img.id = u.imageId
            LEFT JOIN maritalstatus ms ON ms.id = upa.maritalStatusId
            LEFT JOIN addresses addr ON addr.id = upa.addressId
            LEFT JOIN religion r ON r.id = upa.religionId
            LEFT JOIN community c ON c.id = upa.communityId
            LEFT JOIN occupation o ON o.id = upa.occupationId
            LEFT JOIN education e ON e.id = upa.educationId
            LEFT JOIN subcommunity sc ON sc.id = upa.subCommunityId
            LEFT JOIN annualincome ai ON ai.id = upa.annualIncomeId
            LEFT JOIN diet d ON d.id = upa.dietId
            LEFT JOIN height h ON h.id = upa.heightId
            WHERE ur.roleId = 2 AND u.id != ` + userId + ` AND (upa.userId = u.id) AND u.id  AND
            (
                        u.id IN (select userBlockId from userblock where userId = ` + userId + `) = 0
                        AND
                        u.id IN (select userId from userblock where userBlockId = ` + userId + `) = 0
                        )`;

            if (req.body.name) {
                sql += ` AND (u.firstName LIKE '%` + req.body.name + `%')`;
            }
            if (req.body.gender) {
                sql += ` AND u.gender = '` + req.body.gender + `'`;
            }
            if (req.body.occupationId && req.body.occupationId.length) {
                sql += ` AND o.id in (` + req.body.occupationId.toString() + `)`;
            }
            if (req.body.educationId && req.body.educationId.length) {
                sql += ` AND e.id in( ` + req.body.educationId.toString() + `)`;
            }
            if (req.body.maritalStatusId && req.body.maritalStatusId.length) {
                sql += ` AND ms.id in(` + req.body.maritalStatusId.toString() + `)`;
            }
            if (req.body.height1 && req.body.height2) {
                sql += ` AND h.name BETWEEN ` + req.body.height1 + ` AND ` + req.body.height2 + ``;
            }
            if (req.body.cityName) {
                sql += ` AND (addr.cityName LIKE '%` + req.body.cityName + `%')`
            }
            if (req.body.stateId) {
                sql += ` AND st.id = ` + req.body.stateId;
            }
            if (req.body.age1 && req.body.age2) {
                sql += ` AND DATE_FORMAT(FROM_DAYS(DATEDIFF(NOW(), upa.birthDate)), '%Y') + 0 BETWEEN ` + req.body.age1 + ` AND ` + req.body.age2 + ``;
            }
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Search User Successfully', result, result.length, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'users.searchUser() Exception', error, '');
        next(errorResult);
    }
};

const updateUserFlagValues = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Update User Flag Values');
        let requiredFields = ['id', 'userFlagId', 'userFlagValue'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let userId = currentUser.id;
                let sql = `UPDATE userflagvalues SET userFlagId = ` + req.body.userFlagId + `, userFlagValue = ` + req.body.userFlagValue + ` WHERE id = ` + req.body.id;
                let result = await query(sql);
                if (result && result.affectedRows > 0) {
                    let successResult = new ResultSuccess(200, true, 'Update User Flag Value successfully!', result, 1, "null");
                    return res.status(200).send(successResult);
                } else {
                    await rollback();
                    let errorResult = new ResultError(400, true, "users.updateUserFlagValues() Error", new Error('Error While Upadating Data'), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
                next(errorResult);
            }
        } else {
            await rollback();
            let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.updateUserFlagValues() Exception', error, '');
        next(errorResult);
    }
}

const validateAuthToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Validate auth token');
        let authorization = '';
        if (req.headers['authorization'] != undefined && req.headers['authorization'] != '') {
            let authorizationHeader = req.headers['authorization'];
            if (authorizationHeader.indexOf('|') > 0) {
                authorization = authorizationHeader.split('|')[1];
            } else {
                authorization = authorizationHeader;
            }
            if (authorization != '') {
                let token = authorization?.split(' ')[1];
                if (token) {
                    await jwt.verify(token, config.server.token.secret, async (error: any, decoded: any) => {
                        if (error) {
                            let errorResult = new ResultError(401, true, "Unauthorized request", new Error("Unauthorized request"), '');
                            next(errorResult);
                        } else {
                            let decodeVal = decoded;
                            let currentUser;//= await getcurrentUser(decodeVal.userId);
                            let userSql = `SELECT * FROM users WHERE id = ` + decodeVal.userId;
                            let userResult = await query(userSql);
                            if (userResult && userResult.length > 0) {
                                let roleSql = `SELECT roleId,roles.name as roleName FROM userroles INNER JOIN roles  ON  roles.id = userroles.roleId WHERE userId =` + decodeVal.userId;
                                let roleResult = await query(roleSql);
                                let roles = {
                                    id: roleResult[0].roleId,
                                    name: roleResult[0].roleName
                                };

                                let data = new Users(
                                    userResult[0].id,
                                    userResult[0].firstName,
                                    userResult[0].middleName,
                                    userResult[0].lastName,
                                    userResult[0].contactNo,
                                    userResult[0].email,
                                    userResult[0].gender,
                                    userResult[0].password,
                                    userResult[0].imageId,
                                    userResult[0].isPasswordSet,
                                    userResult[0].isDisable,
                                    userResult[0].isVerified,
                                    userResult[0].isActive,
                                    userResult[0].isDelete,
                                    userResult[0].createdDate,
                                    userResult[0].modifiedDate,
                                    userResult[0].createdBy,
                                    userResult[0].modifiedBy,
                                    roles.id,
                                    roles,
                                    ""
                                );
                                currentUser = data;
                                currentUser.token = token;
                                let successResult = new ResultSuccess(200, true, "Session Validate", [currentUser, currentUser.token], 1, "null");
                                return res.status(200).send(successResult);
                            } else {
                                let errorResult = new ResultError(300, true, "User not available.", new Error("User not available."), '');
                                next(errorResult);
                            }
                        }
                    });
                } else {
                    let errorResult = new ResultError(300, true, "Authorization header is required.", new Error("Authorization header is required."), '');
                    next(errorResult);
                }
            } else {
                let errorResult = new ResultError(300, true, "Authorization header is required.", new Error("Authorization header is required."), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error("Unauthorized request"), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'users.validateAuthToken() Exception', error, '');
        next(errorResult);
    }
}

export default { verifyEmailContact, signUp, login, getMasterData, updateUserProfilePic, getAllUsers, viewUserDetail, updateUserProfileDetail, forgotPassword, verifyforgotPasswordLink, resetPassword, changePassword, changeContact, changeEmail, searchUser, updateUserFlagValues, validateAuthToken };