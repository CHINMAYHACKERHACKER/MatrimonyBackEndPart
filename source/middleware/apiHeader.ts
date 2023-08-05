import jwt from 'jsonwebtoken';
import { NextFunction, Request, Response } from 'express';
import { Users } from '../classes/output/admin/users';
import config from '../config/config';
import logging from '../config/logging';
import signJWT from '../function/signJTW';

const mysql = require('mysql');
const util = require('util');

const NAMESPACE = 'API Header';

let connection = mysql.createConnection({
    host: config.mysql.host,
    user: config.mysql.user,
    password: config.mysql.password,
    database: config.mysql.database
});

const query = util.promisify(connection.query).bind(connection);

const validateAuthorization = async (request: Request, res: Response, next: NextFunction) => {
    //, requiredFields
    logging.info(NAMESPACE, 'Validating Request Body');
    let keys = Object.keys(request.body);
    let message = '';
    let _currentUser: any;
    let _token = '';
    let currentUserDevice = {
        app: "",
        appVersion: "",
        fcmToken: "",
        deviceId: "",
        deviceLocation: "",
        deviceManufacturer: "",
        deviceModel: "",
        apiCallTime: ""
    };
    let authorization = '';
    let requestUrl = request.originalUrl;
    // console.log('Request URL:' + requestUrl);
    let statusCode = 200;
    if (request.headers['authorization'] != undefined && request.headers['authorization'] != '') {
        try {
            let deviceData = request.headers['deviceinfo'];
            if (deviceData) {
                currentUserDevice = JSON.parse(JSON.parse(JSON.stringify(deviceData)));
            }

            let authorizationHeader = request.headers['authorization'];
            if (authorizationHeader.indexOf('|') > 0) {
                currentUserDevice.app = authorizationHeader.split('|')[0];
                authorization = authorizationHeader.split('|')[1];
            } else {
                currentUserDevice.app = authorizationHeader;
                authorization = authorizationHeader;
            }

            currentUserDevice.apiCallTime = new Date().toISOString();
            // console.log(JSON.stringify(currentUserDevice));

            if (config.baseRequests.indexOf(requestUrl) == -1) {
                try {
                    if (authorization != '') {
                        let token = authorization?.split(' ')[1];
                        if (token) {
                            await jwt.verify(token, config.server.token.secret, async (error: any, decoded: any) => {
                                if (error) {
                                    let accessToken = request.headers['refreshtoken'];
                                    if (accessToken) {
                                        let refreshResult = await query("SELECT * FROM userrefreshtoken WHERE refreshToken = '" + accessToken + "'");
                                        if (refreshResult && refreshResult.length > 0) {
                                            if (new Date(refreshResult[0].expireAt).getTime() > new Date().getTime()) {
                                                let obj = {
                                                    "id": refreshResult[0].userId
                                                }
                                                let signJWTResult: any = await signJWT(obj);
                                                if (signJWTResult && signJWTResult.token) {
                                                    _currentUser = await getcurrentUser(obj.id);
                                                    _currentUser.token = signJWTResult.token;
                                                    _token = signJWTResult.token;
                                                } else {
                                                    statusCode = 401;
                                                    message = 'Unable to Sign JWT';
                                                }
                                            } else {
                                                statusCode = 401;
                                                message = "UnAuthorize";
                                            }
                                        } else {
                                            statusCode = 401;
                                            message = "UnAuthorize";
                                        }
                                    } else {
                                        statusCode = 401;
                                        message = "UnAuthorize";
                                    }
                                } else {
                                    let decodeVal = decoded;
                                    _currentUser = await getcurrentUser(decodeVal.userId);
                                    _currentUser.token = token;
                                }
                            });
                        } else {
                            statusCode = 300;
                            message = 'Authorization header is required.';
                        }
                    } else {
                        statusCode = 300;
                        message = 'Authorization header is required.';
                    }
                } catch (error: any) {
                    statusCode = error.code;
                    message = error.message;
                }
            }
        } catch (error: any) {
            statusCode = 500;
            message = error.message;
        }
    } else {
        statusCode = 401;
        message = 'Unauthorized request';
    }

    let resultObj = {
        statusCode: statusCode,
        message: message,
        currentUser: _currentUser,
        currentUserDevice: currentUserDevice,
        validate: message != '' ? false : true,
        token: _token
    };
    //if (statusCode == 200) {
        return resultObj;
    //} else {
    //    return resultObj;
    //}
};

const parseFieldValue = (field: any, value: any) => {
    if (field.endsWith('Date')) {
        value = new Date(new Date(value).getFullYear(), new Date(value).getMonth(), new Date(value).getDate());
    } else if (['skip', 'limit'].includes(field) || field.endsWith('Number') || field.endsWith('Days') || field.endsWith('Range')) {
        if (value.indexOf(',') > 0) {
            value = value.split(',');
            value.forEach((v: any, index: number) => {
                value[index] = Number(v);
            });
        } else {
            value = Number(value);
        }
    } else if (field.startsWith('is') && !field.startsWith('iso')) {
        value = JSON.parse(value);
    } else if (value.indexOf(',') > 0) {
        value = value.split(',');
    }
    return value;
};

const validateField = (request: any, field: any) => {
    let message = '';
    let keys = Object.keys(request.body);
    let optionalField = false;
    if (field.indexOf('[') == 0) {
        optionalField = true;
        field = field.substring(1, field.length - 1);
    }
    if (field.indexOf('=') > -1) {
        let fieldValue = field.split('=')[1];
        field = field.split('=')[0];
        fieldValue = parseFieldValue(field, fieldValue);
        let reqFieldValue = request.body[field];
        if (Array.isArray(fieldValue)) {
            if (reqFieldValue != undefined) {
                if (!fieldValue.includes(reqFieldValue)) {
                    message += ', ' + field + ' value must be any of (' + fieldValue.join(', ') + ')';
                }
            } else {
                if (!optionalField) {
                    message += ', ' + field + ' value must be any of (' + fieldValue.join(', ') + ')';
                }
            }
        } else if (fieldValue != reqFieldValue) {
            message += ', ' + field + ' value must be ' + fieldValue;
        }
    } else {
        if (field.indexOf('[') == -1) {
            if (!keys.includes(field)) {
                message += ', ' + field + ' is required';
            }
            if (request.body[field] == null) {
                message += ', ' + field + ' value must required';
            }
        }
    }
    return message;
};

const validateRequiredFields = (request: any, requiredFields: any) => {
    let keys = Object.keys(request.body);
    let index = 0;
    let message = '';
    let statusCode = 200;
    if (requiredFields != '' && requiredFields != undefined) {
        requiredFields.some((field: any) => {
            if (field.indexOf(':') > -1) {
                let childFieldFormat = field.split(':')[0];
                let childField = '';
                let childFieldValue = '';
                if (childFieldFormat.indexOf('=') > -1) {
                    childFieldValue = field.split('=')[1];
                    childField = childFieldFormat.split('=')[0];
                    childFieldValue = parseFieldValue(childField, childFieldValue);
                } else {
                    childField = childFieldFormat;
                }
                let parentField = field.split(':')[1];
                if (parentField.indexOf('=') > -1) {
                    let parentFieldValue = parentField.split('=')[1];
                    parentField = parentField.split('=')[0];
                    parentFieldValue = parseFieldValue(parentField, parentFieldValue);
                    let parentReqFieldValue = request.body[parentField];
                    if (Array.isArray(parentFieldValue)) {
                        if (parentFieldValue.includes(parentReqFieldValue)) {
                            if (!keys.includes(childField)) {
                                message += ', ' + parentField + ' = ' + parentReqFieldValue + ' so ' + childField + ' is required';
                            } else {
                                message += validateField(request, childFieldFormat);
                            }
                        }
                    } else if (parentFieldValue == parentReqFieldValue) {
                        if (!keys.includes(childField)) {
                            message += ', ' + parentField + ' = ' + parentReqFieldValue + ' so ' + childField + ' is required';
                        } else {
                            message += validateField(request, childFieldFormat);
                        }
                    }
                } else if (keys.includes(parentField)) {
                    if (!keys.includes(childField)) {
                        message += ', ' + parentField + ' is passed. So ' + childField + ' is required';
                    } else {
                        message += validateField(request, childFieldFormat);
                    }
                }
            } else {
                message += validateField(request, field);
            }
        });
    }
    // console.log('====>' + message);
    if (message == '') {
        while (index < keys.length) {
            let value = request.body[keys[index]];
            if (value != null || value != undefined) {
                if (value === "") {
                    message = keys[index] + " is required. If blank then please don't pass.";
                    break;
                    // } else if (keys[index].endsWith('Date')) {
                    //     if (!Date.parse(value)) {
                    //         message = keys[index] + ' - date format (yyyy-mm-dd) is required';
                    //         break;
                    //     } else {
                    //         let dateValue = new Date(value);
                    //         request.body[keys[index]] = new Date(dateValue.getFullYear(), dateValue.getMonth(), dateValue.getDate());
                    //     }
                } else if (['skip', 'limit'].includes(keys[index]) || keys[index].endsWith('Days') || keys[index].endsWith('Range')) {
                    if (!Number.isInteger(value)) {
                        message = keys[index] + ' - number datatype is required';
                        break;
                    }
                } else if (keys[index].startsWith('is') && !keys[index].startsWith('iso')) {
                    if (!(typeof value == 'boolean')) {
                        message = keys[index] + ' - boolean datatype is required';
                        break;
                    }
                }
                // else if (pluralize.isPlural(keys[index])) {
                //     // if (!Array.isArray(value)) {
                //     //     message = keys[index] + ' - Array datatype is required';
                //     //     break;
                //     // } else if (value.length == 0) {
                //     //     message = keys[index] + ' - Array is blank.';
                //     //     break;
                //     // }
                // }
            } else {
                request.body[keys[index]] = null;
                // message = keys[index] + " is required.";
                // break;
            }
            index++;
        }
    }
    if (message.length > 0) {
        statusCode = 300;
        message = message.indexOf(',') == 1 ? message.substring(2) : message;
    }
    let resultObj = {
        statusCode: statusCode,
        message: message,
        validate: message != '' ? false : true
    };
    return resultObj;
};

const getcurrentUser = async (userId: number) => {
    try {
        let _currentUser: any;
        let userSql = `SELECT * FROM users WHERE id = ` + userId;
        let userResult = await query(userSql);
        if (userResult && userResult.length > 0) {
            let roleSql = `SELECT roleId,roles.name as roleName FROM userroles INNER JOIN roles  ON  roles.id = userroles.roleId WHERE userId =` + userId;
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
            _currentUser = data;
        }
        return _currentUser;
    } catch (error) {

    }
}

export default { validateAuthorization, parseFieldValue, validateField, validateRequiredFields };