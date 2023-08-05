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

const NAMESPACE = 'Dashboard';

const getDashboardData = async (req: Request, res: Response, next: NextFunction) => {
    try {
        logging.info(NAMESPACE, 'Getting Users');
        let authorizationResult = await header.validateAuthorization(req, res, next);
        if (authorizationResult.statusCode == 200) {
            let currentUser = authorizationResult.currentUser;
            let userId = currentUser.id;
            let fromDate;
            let toDate;
            if (req.body.toDate != undefined && req.body.fromDate != undefined) {
            fromDate = new Date(req.body.fromDate).getFullYear() + "-" + ("0" + (new Date(req.body.fromDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.fromDate).getDate()).slice(-2) + "";
            toDate = new Date(req.body.toDate).getFullYear() + "-" + ("0" + (new Date(req.body.toDate).getMonth() + 1)).slice(-2) + "-" + ("0" + new Date(req.body.toDate).getDate()).slice(-2) + "";
            }
            let todayRegCount = `SELECT COUNT(*) as todayRegistrationCount FROM users WHERE DATE(createdDate) = CURRENT_DATE()`;
            let todayRegCountResult = await query(todayRegCount);

            let monthlyRegCount = `SELECT COUNT(*) as monthlyRegistrationCount FROM users`;
            if (req.body.toDate && req.body.fromDate) {
                monthlyRegCount += ` WHERE DATE(createdDate) >= DATE('` + fromDate + `') AND DATE(createdDate) <= DATE('` + toDate + `')`;
            }else{
                monthlyRegCount += ` WHERE MONTH(createdDate) = MONTH(CURRENT_TIMESTAMP)`
            }
            let monthlyRegCountResult = await query(monthlyRegCount);

            let todayPropsalCount = `SELECT COUNT(*) as todayProposalCount FROM userproposals WHERE DATE(createdDate) = CURRENT_DATE()`;
            let todayPropsalCountResult = await query(todayPropsalCount);

            let monthlyProposalCount = `SELECT COUNT(*) as monthlyProposalCount FROM userproposals`;
            if (req.body.toDate && req.body.fromDate) {
                monthlyProposalCount += ` WHERE DATE(createdDate) >= DATE('` + fromDate + `') AND DATE(createdDate) <= DATE('` + toDate + `')`;
            }else{
                monthlyProposalCount += ` WHERE MONTH(createdDate) = MONTH(CURRENT_TIMESTAMP)`;
            }
            let monthlyProposalCountResult = await query(monthlyProposalCount);

            let recentUser = `SELECT * FROM users WHERE id != ` + userId ;
            if (req.body.toDate && req.body.fromDate) {
                recentUser += ` AND DATE(users.createdDate) >= DATE('` + fromDate + `') AND DATE(users.createdDate) <= DATE('` + toDate + `')`;
            }
            recentUser += ` ORDER BY createdDate desc LIMIT 10`
            let recentUserResult = await query(recentUser);

            let monthlyRegUserCount = `SELECT MONTHNAME(users.createdDate) as month, count(users.id) as usersCount FROM users
            LEFT JOIN userroles ur ON ur.userId = users.id WHERE ur.roleId = 2 `;
            if (req.body.toDate && req.body.fromDate) {
                monthlyRegUserCount += ` AND DATE(users.createdDate) >= DATE('` + fromDate + `') AND DATE(users.createdDate) <= DATE('` + toDate + `')`;
            }
            // if (req.body.year) {
            //     monthlyRegUserCount += ` AND year(users.createdDate) = ` + req.body.year;
            // }
             else {
                monthlyRegUserCount += ` AND year(users.createdDate) = YEAR(CURRENT_TIMESTAMP())`;
            }
            monthlyRegUserCount += ` group by month`;
            let monthlyRegUserCountResult = await query(monthlyRegUserCount);
            let monthlyRegUserCountData = [
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
            for (let index = 0; index < monthlyRegUserCountResult.length; index++) {
                let MonthName = monthlyRegUserCountResult[index].month;
                for (let j = 0; j < monthlyRegUserCountData.length; j++) {
                    if (monthlyRegUserCountData[j].month == MonthName) {
                        monthlyRegUserCountData[j].count = monthlyRegUserCountResult[index].usersCount;
                    }
                }
            }

            let result = [{
                "todayRegistration" : todayRegCountResult[0].todayRegistrationCount,
                "monthlyRegistration" : monthlyRegCountResult[0].monthlyRegistrationCount,
                "todayProposal" : todayPropsalCountResult[0].todayProposalCount,
                "monthlyProposal" : monthlyProposalCountResult[0].monthlyProposalCount,
                "recentUserResult" : recentUserResult,
                "monthlyRegUserCount" : monthlyRegUserCountData
            }]
            if (result && result.length > 0) {
                let successResult = new ResultSuccess(200, true, 'Get Users Successfully', result, result.length, authorizationResult.token);
                return res.status(200).send(successResult);
            }
            else {
                let errorResult = new ResultError(401, true, "Unauthorized request", new Error(authorizationResult.message), '');
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

export default { getDashboardData }