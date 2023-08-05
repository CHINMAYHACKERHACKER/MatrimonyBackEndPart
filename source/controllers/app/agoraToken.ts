import { NextFunction, Request, Response } from 'express';
import logging from "../../config/logging";
import config from "../../config/config";
import header from "../../middleware/apiHeader";
import { ResultSuccess } from '../../classes/response/resultsuccess';
import { ResultError } from '../../classes/response/resulterror';

const mysql = require('mysql');
const util = require('util');
var {RtcTokenBuilder} = require('agora-access-token')

let connection = mysql.createConnection({
    host: config.mysql.host,
    user: config.mysql.user,
    password: config.mysql.password,
    database: config.mysql.database
});

const query = util.promisify(connection.query).bind(connection);

const NAMESPACE = 'AgoraToken';

var expirationTimeInSeconds = 3600;

const getAgoraToken = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Users AgoraToken');
        let requiredFields = ['channelName','uid'];
        let validationResult = header.validateRequiredFields(req, requiredFields);
        if (validationResult && validationResult.statusCode == 200) {
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
          var currentTimestamp = Math.floor(Date.now() / 1000)
          var privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds
          var channelName = req.body.channelName;
          // use 0 if uid is not specified
          var uid = req.body.uid || 0
            let sql = `SELECT * FROM systemflags WHERE flagGroupId = 7 AND VALUE IS NOT NULL;`;
            let agora = await query(sql);
            let appid = agora[0].value;
            console.log(appid);
            let appcerti = agora[1].value;
            console.log(appcerti);
          var key = RtcTokenBuilder.buildTokenWithUid(agora[0].value, agora[1].value, channelName, uid, privilegeExpiredTs);
            let result = key;
          let successResult = new ResultSuccess(200, true, 'Access Token', result, 1, "");
              return res.status(200).send(successResult);
        }
         }
         else {
          let errorResult = new ResultError(validationResult.statusCode, true, validationResult.message, new Error(validationResult.message), '');
          next(errorResult);
      }
    }catch (error: any) {
        let errorResult = new ResultError(500, true, 'agoraToken.getAgoraToken() Exception', error, '');
        next(errorResult);
    }
};

export default {getAgoraToken};