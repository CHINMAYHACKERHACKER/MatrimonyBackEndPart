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

const NAMESPACE = 'Report';

const getMasterEntryData = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Application User');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {

            let occupationSql = `SELECT * FROM occupation WHERE isActive = 1`;
            let occupationResult = await query(occupationSql);

            let educationSql = `SELECT * FROM education WHERE isActive = 1`;
            let educationResult = await query(educationSql);

            let maritalStatusSql = `SELECT * FROM maritalstatus WHERE isActive = 1`;
            let maritalStatusResult = await query(maritalStatusSql);

            let religionSql = `SELECT * FROM religion WHERE isActive = 1`;
            let religionResult = await query(religionSql);

            let communitySql = `SELECT * FROM community WHERE isActive = 1`;
            let communityResult = await query(communitySql);

            let subCommunitySql = `SELECT * FROM subcommunity WHERE isActive = 1`;
            let subCommunityResult = await query(subCommunitySql);

            let dietSql = `SELECT * FROM diet WHERE isActive = 1`;
            let dietResult = await query(dietSql);

            let heightSql = `SELECT * FROM height WHERE isActive = 1`;
            let heightResult = await query(heightSql);

            let annualIncomeSql = `SELECT * FROM annualincome WHERE isActive = 1`;
            let annualIncomeResult = await query(annualIncomeSql);

            let result = [{
                "occupation": occupationResult,
                "education": educationResult,
                "maritalStatus": maritalStatusResult,
                "religion": religionResult,
                "community": communityResult,
                "subCommunity": subCommunityResult,
                "diet": dietResult,
                "height": heightResult,
                "annualIncome": annualIncomeResult
            }]

            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get Application User Report Successfully', result, result.length, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getApplicationUserReport() Exception', error, '');
        next(errorResult);
    }
};

const getApplicationUserReport = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Application User');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = `SELECT count(*) as totalRecords FROM users u
            LEFT JOIN userroles ur ON ur.userId = u.id
            LEFT JOIN userpersonaldetail upa ON u.id = upa.userId
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
            WHERE ur.roleId = 2 AND u.firstName IS NOT NUll`;
            if (req.body.name) {
                countSql += ` AND (u.firstName LIKE '%` + req.body.name + `%')`;
            }
            if (req.body.gender) {
                countSql += ` AND (u.gender = '` + req.body.gender + `')`;
            }
            if (req.body.occupationId) {
                countSql += ` AND o.id = ` + req.body.occupationId + ``;
            }
            if (req.body.educationId) {
                countSql += ` AND e.id = ` + req.body.educationId;
            }
            if (req.body.religionId) {
                countSql += ` AND r.id = ` + req.body.religionId;
            }
            if (req.body.communityId) {
                countSql += ` AND c.id = ` + req.body.communityId;
            }
            if (req.body.subCommunityId) {
                countSql += ` AND sc.id = ` + req.body.subCommunityId;
            }
            if (req.body.maritalStatusId) {
                countSql += ` AND ms.id = ` + req.body.maritalStatusId;
            }
            if (req.body.incomeId) {
                countSql += ` AND ai.id = ` + req.body.incomeId;
            }
            if (req.body.dietId) {
                countSql += ` AND d.id = ` + req.body.dietId;
            }
            if (req.body.heightId) {
                countSql += ` AND h.id = ` + req.body.heightId;
            }
            if (req.body.cityName) {
                countSql += ` AND addr.cityName = '` + req.body.cityName + "'";
            }
            if (req.body.stateName) {
                countSql += ` AND addr.stateName = '` + req.body.stateName + "'";
            }
            if (req.body.countryName) {
                countSql += ` AND addr.countryName = '` + req.body.countryName + "'";
            }
            let countResult = await query(countSql);

            let sql = `SELECT upa.id, upa.userId, img.imageUrl, u.firstName, u.middleName, u.lastName, u.contactNo, u.email, u.gender, u.createdDate, upa.birthDate, upa.eyeColor, upa.languages, addr.addressLine1, addr.addressLine2, addr.pincode, addr.cityName as cityName, addr.stateName as stateName, ms.name as maritalStatus, r.name as religion, c.name as community, o.name as occupation, e.name as education, sc.name as subCommunity, ai.value as annualIncome, d.name as diet, h.name as height
            FROM users u
            LEFT JOIN userpersonaldetail upa ON u.id = upa.userId
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
            WHERE ur.roleId = 2 AND u.firstName IS NOT NUll`;

            if (req.body.name) {
                sql += ` AND (u.firstName LIKE '%` + req.body.name + `%')`;
            }
            if (req.body.gender) {
                sql += ` AND (u.gender = '` + req.body.gender + `')`;
            }
            if (req.body.occupationId) {
                sql += ` AND o.id = ` + req.body.occupationId + ``;
            }
            if (req.body.educationId) {
                sql += ` AND e.id = ` + req.body.educationId;
            }
            if (req.body.religionId) {
                sql += ` AND r.id = ` + req.body.religionId;
            }
            if (req.body.communityId) {
                sql += ` AND c.id = ` + req.body.communityId;
            }
            if (req.body.subCommunityId) {
                sql += ` AND sc.id = ` + req.body.subCommunityId;
            }
            if (req.body.maritalStatusId) {
                sql += ` AND ms.id = ` + req.body.maritalStatusId;
            }
            if (req.body.incomeId) {
                sql += ` AND ai.id = ` + req.body.incomeId;
            }
            if (req.body.dietId) {
                sql += ` AND d.id = ` + req.body.dietId;
            }
            if (req.body.heightId) {
                sql += ` AND h.id = ` + req.body.heightId;
            }
            if (req.body.cityName) {
                sql += ` AND addr.cityName = '` + req.body.cityName + "'";
            }
            if (req.body.stateName) {
                sql += ` AND addr.stateName = '` + req.body.stateName + "'";
            }
            if (req.body.countryName) {
                sql += ` AND addr.countryName = '` + req.body.countryName + "'";
            }
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result && result.length >= 0) {
                let successResult = new ResultSuccess(200, true, 'Get Application User Report Successfully', result, countResult[0].totalRecords, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getApplicationUserReport() Exception', error, '');
        next(errorResult);
    }
};

const getSendProposalReqReport = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Send Proposal Request');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let fromDate;
            let toDate;
            if (req.body.toDate != undefined && req.body.fromDate != undefined) {
                fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
                toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            }
            let sql = `SELECT MONTHNAME(up.createdDate) as month, count(up.userId) as sendRequest FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN userroles ur ON ur.userId = u.id
            WHERE ur.roleId = 2`;
            if (req.body.year) {
                sql += ` AND year(up.createdDate) = ` + req.body.year;
            }
            else {
                sql += ` AND year(up.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            if (req.body.toDate && req.body.fromDate) {
                sql += ` AND DATE(up.createdDate) >= DATE('` + fromDate + `') AND DATE(up.createdDate) <= DATE('` + toDate + `')`;
            }

            sql += ` group by month`

            let result = await query(sql);
            if (result && result.length >= 0) {
                let data = [
                    {
                        "month": "January",
                        "count": 0
                    },
                    {
                        "month": "February",
                        "count": 0
                    },
                    {
                        "month": "March",
                        "count": 0
                    },
                    {
                        "month": "April",
                        "count": 0
                    },
                    {
                        "month": "May",
                        "count": 0
                    },
                    {
                        "month": "June",
                        "count": 0
                    },
                    {
                        "month": "July",
                        "count": 0
                    },
                    {
                        "month": "August",
                        "count": 0
                    },
                    {
                        "month": "September",
                        "count": 0
                    },
                    {
                        "month": "October",
                        "count": 0
                    },
                    {
                        "month": "November",
                        "count": 0
                    },
                    {
                        "month": "December",
                        "count": 0
                    },
                ]
                for (let index = 0; index < result.length; index++) {
                    let MonthName = result[index].month;
                    for (let j = 0; j < data.length; j++) {
                        if (data[j].month == MonthName) {
                            data[j].count = result[index].sendRequest;
                        }
                    }
                }
                let successResult = new ResultSuccess(200, true, 'Get Send Proposal Request Report Successfully', data, result.length, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getSendProposalReqReport() Exception', error, '');
        next(errorResult);
    }
};

const getReceiveProposalReqReport = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Receive Proposal Request ');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let fromDate;
            let toDate;
            if (req.body.toDate != undefined && req.body.fromDate != undefined) {
                fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
                toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            }
            let sql = `SELECT MONTHNAME(up.createdDate) as month, count(up.userId) as receiveRequest FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN userroles ur ON ur.userId = u.id
            WHERE ur.roleId = 2 AND up.status = 1`;
            if (req.body.year) {
                sql += ` AND year(up.createdDate) = ` + req.body.year;
            }
            else {
                sql += ` AND year(up.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            if (req.body.toDate && req.body.fromDate) {
                sql += ` AND DATE(up.createdDate) >= DATE('` + fromDate + `') AND DATE(up.createdDate) <= DATE('` + toDate + `')`;
            }
            sql += ` group by month`

            let result = await query(sql);
            if (result && result.length >= 0) {
                let data = [
                    {
                        "month": "January",
                        "count": 0
                    },
                    {
                        "month": "February",
                        "count": 0
                    },
                    {
                        "month": "March",
                        "count": 0
                    },
                    {
                        "month": "April",
                        "count": 0
                    },
                    {
                        "month": "May",
                        "count": 0
                    },
                    {
                        "month": "June",
                        "count": 0
                    },
                    {
                        "month": "July",
                        "count": 0
                    },
                    {
                        "month": "August",
                        "count": 0
                    },
                    {
                        "month": "September",
                        "count": 0
                    },
                    {
                        "month": "October",
                        "count": 0
                    },
                    {
                        "month": "November",
                        "count": 0
                    },
                    {
                        "month": "December",
                        "count": 0
                    },
                ]
                for (let index = 0; index < result.length; index++) {
                    let MonthName = result[index].month;
                    for (let j = 0; j < data.length; j++) {
                        if (data[j].month == MonthName) {
                            data[j].count = result[index].receiveRequest
                        }
                    }
                }
                let successResult = new ResultSuccess(200, true, 'Get Receive Proposal Request Successfully', data, result.length, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getReceiveProposalReqReport() Exception', error, '');
        next(errorResult);
    }
};

const getRejectProposalReqReport = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Reject Proposal Request');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let fromDate;
            let toDate;
            if (req.body.toDate != undefined && req.body.fromDate != undefined) {
                fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
                toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            }
            let sql = `SELECT MONTHNAME(up.createdDate) as month, count(up.userId) as rejectRequest FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN userroles ur ON ur.userId = u.id
            WHERE ur.roleId = 2 AND up.status = 0`;
            if (req.body.year) {
                sql += ` AND year(up.createdDate) = ` + req.body.year;
            }
            else {
                sql += ` AND year(up.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            if (req.body.toDate && req.body.fromDate) {
                sql += ` AND DATE(up.createdDate) >= DATE('` + fromDate + `') AND DATE(up.createdDate) <= DATE('` + toDate + `')`;
            }

            sql += ` group by month`

            let result = await query(sql);
            if (result && result.length >= 0) {
                let data = [
                    {
                        "month": "January",
                        "count": 0
                    },
                    {
                        "month": "February",
                        "count": 0
                    },
                    {
                        "month": "March",
                        "count": 0
                    },
                    {
                        "month": "April",
                        "count": 0
                    },
                    {
                        "month": "May",
                        "count": 0
                    },
                    {
                        "month": "June",
                        "count": 0
                    },
                    {
                        "month": "July",
                        "count": 0
                    },
                    {
                        "month": "August",
                        "count": 0
                    },
                    {
                        "month": "September",
                        "count": 0
                    },
                    {
                        "month": "October",
                        "count": 0
                    },
                    {
                        "month": "November",
                        "count": 0
                    },
                    {
                        "month": "December",
                        "count": 0
                    },
                ]
                for (let index = 0; index < result.length; index++) {
                    let MonthName = result[index].month;
                    for (let j = 0; j < data.length; j++) {
                        if (data[j].month == MonthName) {
                            data[j].count = result[index].rejectRequest
                        }
                    }
                }
                let successResult = new ResultSuccess(200, true, 'Get Proposal Request Reject Successfully', data, result.length, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getRejectProposalReqReport() Exception', error, '');
        next(errorResult);
    }
};

const getTopProposalSendReqReport = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Top proposal Send Request');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = `SELECT count(Distinct up.userId) as totalRecords from userproposals up ;`
            // let countSql = `SELECT COUNT(*) as totalRecords from (SELECT up.userId FROM userproposals as up
            //     group by up.userId ) as totalProposal`;
            let countResult = await query(countSql);
            let sql = `select Distinct up.userId,(select count(t2.userId) from userproposals as t2 where t2.userId=up.userId ) as sendRequest,u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo from userproposals up 
            left join users u on u.id=up.userId
            LEFT JOIN images AS img ON img.id = u.imageId
            ORDER BY sendRequest DESC`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result && result.length >= 0) {
                let successResult = new ResultSuccess(200, true, 'Get Top proposal Send Request Report Successfully', result, countResult[0].totalRecords, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getTopProposalSendReqReport() Exception', error, '');
        next(errorResult);
    }
};

const getTopProposalReceiveReqReport = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Top proposal Receive Request');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let countSql = `SELECT count(Distinct up.proposalUserId) as totalRecords from userproposals up ;`;
            let countResult = await query(countSql);
            let sql = `SELECT Distinct up.proposalUserId,(select count(t2.proposalUserId) from userproposals as t2 where t2.proposalUserId=up.proposalUserId ) as receiveRequest, u.firstName, u.middleName, u.lastName, u.gender, u.email, u.contactNo, img.imageUrl FROM userproposals as up
            LEFT JOIN users u ON u.id = up.proposalUserId
            LEFT JOIN images img ON img.id = u.imageId
            order by receiveRequest desc`;
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result && result.length >= 0) {
                let successResult = new ResultSuccess(200, true, 'Get Top proposal Receive Request Report Successfully', result, countResult[0].totalRecords, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getTopProposalReceiveReqReport() Exception', error, '');
        next(errorResult);
    }
};

const getMonthlySendProposalUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Monthly Send Proposal User');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let fromDate;
            let toDate;
            if (req.body.toDate && req.body.fromDate) {
                fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
                toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            }

            let countSql = `SELECT count(u.id) as totalRecords FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN users usr ON usr.id = up.proposalUserId
            LEFT JOIN userroles ur ON ur.userId = u.id
            WHERE ur.roleId = 2`;
            if (req.body.toDate && req.body.fromDate) {
                countSql += " AND DATE(up.createdDate) >= DATE('" + fromDate + "') AND DATE(up.createdDate) <= DATE('" + toDate + "')";
            } else {
                countSql += ` AND year(up.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            let countResult = await query(countSql);

            let sql = `SELECT u.id, up.proposalUserId, CONCAT(u.firstName,' ', u.lastName) as userName, CONCAT(usr.firstName,' ', usr.lastName) as proposalName, up.createdDate,MONTHNAME(up.createdDate) as month FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN users usr ON usr.id = up.proposalUserId
            LEFT JOIN userroles ur ON ur.userId = u.id
            WHERE ur.roleId = 2 `;
            if (req.body.toDate && req.body.fromDate) {
                sql += " AND DATE(up.createdDate) >= DATE('" + fromDate + "') AND DATE(up.createdDate) <= DATE('" + toDate + "')";
            } else {
                sql += ` AND year(up.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            if (req.body.month) {
                sql += ` AND MONTHNAME(up.createdDate)  = '` + req.body.month + `'`;
            }
            sql += ` order by up.createdDate`

            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result && result.length >= 0) {
                let successResult = new ResultSuccess(200, true, 'Get Month Wise Send Proposal Users Successfully', result, countResult[0].totalRecords, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getMonthlySendProposalUser() Exception', error, '');
        next(errorResult);
    }
};

const getMonthlyReceiveProposalUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Monthly Receive Proposal User');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let fromDate;
            let toDate;
            if (req.body.toDate && req.body.fromDate) {
                fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
                toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            }

            let countSql = `SELECT count(u.id) as totalRecords FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN users usr ON usr.id = up.proposalUserId
            LEFT JOIN userroles ur ON ur.userId = u.id
            WHERE ur.roleId = 2 AND up.status = 1`;
            if (req.body.toDate && req.body.fromDate) {
                countSql += " AND DATE(up.createdDate) >= DATE('" + fromDate + "') AND DATE(up.createdDate) <= DATE('" + toDate + "')";
            }
            else {
                countSql += ` AND year(up.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            // if (req.body.month) {
            //     countSql += ` AND MONTHNAME(up.createdDate) = '` + req.body.month + `'`;
            // }

            let countResult = await query(countSql);

            let sql = `SELECT u.id, up.proposalUserId, CONCAT(u.firstName,' ', u.lastName) as userName, CONCAT(usr.firstName,' ', usr.lastName) as proposalName, up.createdDate, MONTHNAME(up.createdDate) as month FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN users usr ON usr.id = up.proposalUserId
            LEFT JOIN userroles ur ON ur.userId = u.id
            WHERE ur.roleId = 2 AND up.status = 1`;
            if (req.body.toDate && req.body.fromDate) {
                sql += " AND DATE(up.createdDate) >= DATE('" + fromDate + "') AND DATE(up.createdDate) <= DATE('" + toDate + "')";
            } else {
                sql += ` AND year(up.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            // if (req.body.month) {
            //     sql += ` AND MONTHNAME(up.createdDate) = '` + req.body.month + `'`;
            // }
            sql += ` order by up.createdDate`
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result && result.length >= 0) {
                let successResult = new ResultSuccess(200, true, 'Get Monthly Receive Proposal Users Successfully', result, countResult[0].totalRecords, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getMonthlyReceiveProposalUser() Exception', error, '');
        next(errorResult);
    }
};

const getMonthlyRejectProposalUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Monthly Rejected Proposal User');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let fromDate;
            let toDate;
            if (req.body.toDate != undefined && req.body.fromDate != undefined) {
                fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
                toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            }

            let countSql = `SELECT count(u.id) as totalRecords FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN users usr ON usr.id = up.proposalUserId
            LEFT JOIN userroles ur ON ur.userId = u.id
            WHERE ur.roleId = 2 AND up.status = 0`;
            if (req.body.toDate && req.body.fromDate) {
                countSql += " AND DATE(up.createdDate) >= DATE('" + fromDate + "') AND DATE(up.createdDate) <= DATE('" + toDate + "')";
            } else {
                countSql += ` AND year(up.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            // if (req.body.month) {
            //     countSql += ` AND MONTHNAME(up.createdDate) = '` + req.body.month + `'`;
            // }
            let countResult = await query(countSql);

            let sql = `SELECT u.id, up.proposalUserId, CONCAT(u.firstName,' ', u.lastName) as userName, CONCAT(usr.firstName,' ', usr.lastName) as proposalName, up.createdDate, MONTHNAME(up.createdDate) as month FROM userproposals up
            LEFT JOIN users u ON u.id = up.userId
            LEFT JOIN users usr ON usr.id = up.proposalUserId
            LEFT JOIN userroles ur ON ur.userId = u.id
            WHERE ur.roleId = 2 AND up.status = 0`;
            if (req.body.toDate && req.body.fromDate) {
                sql += " AND DATE(up.createdDate) >= DATE('" + fromDate + "') AND DATE(up.createdDate) <= DATE('" + toDate + "')";
            } else {
                sql += ` AND year(up.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            // if (req.body.month) {
            //     sql += ` AND MONTHNAME(up.createdDate) = '` + req.body.month + `'`;
            // }
            sql += ` order by up.createdDate`
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result && result.length >= 0) {
                let successResult = new ResultSuccess(200, true, 'Get Monthly Rejected Proposal Users Successfully', result, countResult[0].totalRecords, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getMonthlyRejectProposalUser() Exception', error, '');
        next(errorResult);
    }
};

const getPremiumAppUser = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Preminum App User');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let fromDate;
            let toDate;
            // if (req.body.toDate != undefined && req.body.fromDate != undefined) {
            // fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
            // toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            // }

            let countSql = `SELECT count(u.id) as totalRecords FROM userpackage up
            Inner JOIN users u on up.userId = u.id
            Inner join package p on up.packageId = p.id
            Inner join packageduration pd on up.packageDurationId = pd.id
            Inner join timeduration td on pd.timeDurationId = td.id
            WHERE DATE(up.startDate)<=DATE(current_timestamp()) AND DATE(up.endDate)>=DATE(current_timestamp())`;
            if (req.body.firstName) {
                if (!countSql.includes(`WHERE`)) {
                    countSql += ` WHERE `;
                } else {
                    countSql += ` AND `;
                }
                countSql += ` u.firstName LIKE '%` + req.body.firstName + `%'`;
            }
            let countResult = await query(countSql);

            let sql = `SELECT u.id as userId,u.firstName,u.lastName,u.gender,u.contactNo,u.email
            , p.id as packageId,p.name as packageName
            , pd.id as packageDurationId,pd.timeDurationId ,td.value
            ,up.netAmount, up.startDate,up.endDate from userpackage up
            Inner JOIN users u on up.userId = u.id
            inner join package p on up.packageId = p.id
            inner join packageduration pd on up.packageDurationId = pd.id
            inner join timeduration td on pd.timeDurationId = td.id
            WHERE DATE(up.startDate)<=DATE(current_timestamp()) AND DATE(up.endDate)>=DATE(current_timestamp())`;
            if (req.body.firstName) {
                if (!sql.includes(`WHERE`)) {
                    sql += ` WHERE `;
                } else {
                    sql += ` AND `;
                }
                sql += ` (u.firstName LIKE '%` + req.body.firstName + `%')`;
            }
            sql += ` order by up.startDate DESC`
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result && result.length >= 0) {
                let successResult = new ResultSuccess(200, true, 'Get Premium App Users Successfully', result, countResult[0].totalRecords, authorizationResult.token);
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
        let errorResult = new ResultError(500, true, 'report.getPremiumAppUser() Exception', error, '');
        next(errorResult);
    }
};

const getSystemBlockedUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting System Blocked Users');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let startIndex = req.body.startIndex ? req.body.startIndex : (req.body.startIndex === 0 ? 0 : null);
            let fetchRecord = req.body.fetchRecord ? req.body.fetchRecord : null;
            let fromDate;
            let toDate;
            if (req.body.toDate != undefined && req.body.fromDate != undefined) {
                fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
                toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            }
            let countSql = `SELECT count(u.id) as totalRecords FROM users u WHERE u.isDisable = 1`;
            if (req.body.toDate && req.body.fromDate) {
                countSql += " AND DATE(u.modifiedDate) >= DATE('" + fromDate + "') AND DATE(u.modifiedDate) <= DATE('" + toDate + "')";
            }
            countSql += ` order by u.modifiedDate DESC`
            let countResult = await query(countSql);

            let sql = `SELECT u.* FROM users u  WHERE u.isDisable = 1 `;
            if (req.body.toDate && req.body.fromDate) {
                sql += " AND DATE(u.modifiedDate) >= DATE('" + fromDate + "') AND DATE(u.modifiedDate) <= DATE('" + toDate + "')";
            }
            sql += ` order by u.modifiedDate DESC`
            if (startIndex != null && fetchRecord != null) {
                sql += " LIMIT " + fetchRecord + " OFFSET " + startIndex + "";
            }
            let result = await query(sql);
            if (result) {
                let successResult = new ResultSuccess(200, true, 'Get System Blocked Users Successfully', result, countResult[0].totalRecords, authorizationResult.token);
                return res.status(200).send(successResult);
            } else {
                let errorResult = new ResultError(400, true, "Data Not Available", new Error('Data Not Available'), '');
                next(errorResult);
            }
        } else {
            let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
            next(errorResult);
        }
    } catch (error: any) {
        let errorResult = new ResultError(500, true, 'report.getSystemBlockedUsers() Exception', error, '');
        next(errorResult);
    }
};

export default { getMasterEntryData, getApplicationUserReport, getSendProposalReqReport, getReceiveProposalReqReport, getRejectProposalReqReport, getTopProposalSendReqReport, getTopProposalReceiveReqReport, getMonthlySendProposalUser, getMonthlyReceiveProposalUser, getMonthlyRejectProposalUser, getPremiumAppUser, getSystemBlockedUsers };