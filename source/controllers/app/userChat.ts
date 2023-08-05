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

const NAMESPACE = 'Chat';

const insertUserChat = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting User Chats');
        let requiredFields = ['partnerId'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let currentUserId = currentUser.id;
                let chatId = currentUserId + "_" + req.body.partnerId
                let sql = `SELECT * from userchat where userId = ` + currentUserId + ` AND partnerId = ` + req.body.partnerId + ` OR userId = ` + req.body.partnerId + ` AND partnerId = ` + currentUserId + ``;
                let result = await query(sql);
                if (result && result.length > 0) {
                    let q1 = ` select u.id,u.firstname,u.lastName,u.imageId as image,i.imageUrl,ch.chatId  from userchat ch 
                    inner join users u on ch.partnerId = u.id
                    left join  images i on u.imageId = i.id
                    WHERE ch.userId = `+ currentUserId;
                    if (req.body.partnerId) {
                        if (!q1.includes(`WHERE`)) {
                            q1 += ` WHERE `;
                        } else {
                            q1 += ` AND `;
                        }
                        q1 += ` ch.partnerId = ` + req.body.partnerId + ` AND (
                            u.id IN (select userBlockId from userblock where userId = ` + currentUserId + `) = 0
                            AND
                            u.id IN (select userId from userblock where userBlockId = ` + currentUserId + `) = 0
                            );`;
                    }
                    let result1 = await query(q1);

                    let q2 = ` select u.id,u.firstname,u.lastName,u.imageId as image,i.imageUrl,ch.chatId  from userchat ch 
                    inner join users u on ch.userId = u.id
                    left join  images i on u.imageId = i.id
                    WHERE ch.partnerId = `+ currentUserId;
                    if (req.body.partnerId) {
                        if (!q2.includes(`WHERE`)) {
                            q2 += ` WHERE `;
                        } else {
                            q2 += ` AND `;
                        }
                        q2 += ` ch.userId = ` + req.body.partnerId + ` AND (
                            u.id IN (select userBlockId from userblock where userId = ` + currentUserId + `) = 0
                            AND
                            u.id IN (select userId from userblock where userBlockId = ` + currentUserId + `) = 0
                            ); `;
                    }
                    let result2 = await query(q2);

                    result = result1.concat(result2)
                    let successResult = new ResultSuccess(200, true, 'user chat Successfully', result, result.length, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    sql = `INSERT INTO userchat(userId, partnerId, chatId, createdBy, modifiedBy) VALUES(` + currentUserId + `,` + req.body.partnerId + `,'` + chatId + `',` + currentUserId + `,` + currentUserId + `)`;
                    let result = await query(sql);
                    let q1 = ` select u.id,u.firstname,u.lastName,u.imageId as image,i.imageUrl,ch.chatId  from userchat ch 
                    inner join users u on ch.partnerId = u.id
                    left join  images i on u.imageId = i.id
                    WHERE ch.userId = `+ currentUserId;
                    if (req.body.partnerId) {
                        if (!q1.includes(`WHERE`)) {
                            q1 += ` WHERE `;
                        } else {
                            q1 += ` AND `;
                        }
                        q1 += ` ch.partnerId = ` + req.body.partnerId;
                    }
                    let result1 = await query(q1);

                    let q2 = ` select u.id,u.firstname,u.lastName,u.imageId as image,i.imageUrl,ch.chatId  from userchat ch 
                    inner join users u on ch.userId = u.id
                    left join  images i on u.imageId = i.id
                    WHERE ch.partnerId = `+ currentUserId;
                    if (req.body.partnerId) {
                        if (!q2.includes(`WHERE`)) {
                            q2 += ` WHERE `;
                        } else {
                            q2 += ` AND `;
                        }
                        q2 += `  ch.userId = ` + req.body.partnerId ;
                    }
                    let result2 = await query(q2);

                    result = result1.concat(result2)
                    let successResult = new ResultSuccess(200, true, 'user chat Successfully', result, result.length, authorizationResult.token);
                    return res.status(200).send(successResult);
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
        let errorResult = new ResultError(500, true, 'userChat.insertUserChat() Exception', error, '');
        next(errorResult);
    }
};

const getUserChatList = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting User Chats');
        let requiredFields = ['startIndex', 'fetchRecord'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
            let authorizationResult = await header.validateAuthorization(req, res, next);
            if (authorizationResult.statusCode == 200) {
                let currentUser = authorizationResult.currentUser;
                let currentUserId = currentUser.id;
                let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
                let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
                let countSql = `SELECT COUNT(*) as totalCount from userchat `;
                let countResult = await query(countSql);
                let sql = `SELECT * from userchat where userId = ` + currentUserId + ` OR partnerId = ` + currentUserId + ``;
                let result = await query(sql);
                if (result && result.length > 0) {

                    let q1 = ` select u.id,u.firstname,u.lastName,i.imageUrl,uc.chatId,ud.fcmToken  from userchat uc 
                    inner join users u on uc.partnerId = u.id
                    left join  images i on u.imageId = i.id 
                    left join userdevicedetail ud on ud.userId = u.id
                    where uc.userId = ` + currentUserId + ` AND (
                        u.id IN (select userBlockId from userblock where userId = ` + currentUserId + `) = 0
                        AND
                        u.id IN (select userId from userblock where userBlockId = ` + currentUserId + `) = 0
                        )`;

                    let q2 = ` select u.id,u.firstname,u.lastName,i.imageUrl,uc.chatId,ud.fcmToken  from userchat uc 
                    inner join users u on uc.userId = u.id
                    left join  images i on u.imageId = i.id 
                    left join userdevicedetail ud on ud.userId = u.id
                    where uc.partnerId = `+ currentUserId + ` AND (
                        u.id IN (select userBlockId from userblock where userId = `+ currentUserId + `) = 0
                        AND
                        u.id IN (select userId from userblock where userBlockId = `+ currentUserId + `) = 0
                        )`;

                    let q = `SELECT * FROM (` + q1 + ` UNION ` + q2 + `)  as t1`

                    if (startIndex != null && fetchRecord != null) {
                        q += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
                    }

                    let result1 = await query(q);

                    result = result1

                    let successResult = new ResultSuccess(200, true, 'Get Chat List Successfully', result, countResult[0].totalCount, authorizationResult.token);
                    return res.status(200).send(successResult);
                } else {
                    let successResult = new ResultSuccess(200, true, 'Get Chat List Successfully', [], countResult[0].totalCount, authorizationResult.token);
                    return res.status(200).send(successResult);
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
        let errorResult = new ResultError(500, true, 'userChat.getUserChatList() Exception', error, '');
        next(errorResult);
    }
};

export default { insertUserChat, getUserChatList };