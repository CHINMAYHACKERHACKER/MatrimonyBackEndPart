import http from 'http';
import express from 'express';
import bodyParser from 'body-parser';
import logging from './config/logging';
import config from './config/config';
import sampleRoutes from './routes/sampleRoutes'
const cors = require('cors');

//#region Admin
import usersRoutes from './routes/admin/usersRoutes';
import dashboardRoutes from './routes/admin/dashboardRoutes';
import annualIncomeRoutes from './routes/admin/annualIncomeRoutes';
import appUsersRoutes from './routes/admin/appUsersRoutes'
import communityRoutes from './routes/admin/communityRoutes';
import dietRoutes from './routes/admin/dietRoutes';
import educationRoutes from './routes/admin/educationRoutes';
import heightRoutes from './routes/admin/heightRoutes';
import maritalStatusRoutes from './routes/admin/maritalStatusRoutes';
import occupationRoutes from './routes/admin/occupationRoutes';
import religionRoutes from './routes/admin/religionRoutes';
import reportRoutes from './routes/admin/reportRoutes';
import subCommunityRoutes from './routes/admin/subCommunityRoutes';
import userBlockReqRoutes from './routes/admin/userBlockRequestRoutes';
import systemFlagsRoutes from './routes/admin/systemFlagsRoutes';
import citiesRoutes from './routes/admin/citiesRoutes';
import statesRoutes from './routes/admin/statesRoutes';
import districtsRoutes from './routes/admin/districtsRoutes';
import employmentType from './routes/admin/employmentTypeRoutes';
import successStory from './routes/admin/successStoriesRoutes';
import premiumAccountType from './routes/admin/premiumAccountTypeRoutes';
import premiumFacility from './routes/admin/premiumFacilityRoutes';
import timeDuration from './routes/admin/timeDurationRoutes';
import userPackage from './routes/admin/packageRoutes';
import feedback from './routes/admin/feedbackRoutes';
import questionCategoriesRoutes from './routes/admin/questionCategoriesRoutes';
//#endregion Admin

//#region App
import userRoutes from './routes/app/usersRoutes';
import homeRoutes from './routes/app/homeRoutes';
import agoraToken from './routes/app/agoraTokenRoutes';
import proposalRoutes from './routes/app/proposalRoutes';
import userBlockRequestRoutes from './routes/app/userBlockRequestRoutes';
import userFavouritesRoutes from './routes/app/userFavouritesRoutes';
import userNotificationsRoutes from './routes/app/userNotificationsRoutes';
import visitorsRoutes from './routes/app/visitorsRoutes';
import userChatRoutes from './routes/app/userChatRoutes';
import feedbackRoutes from './routes/app/feedbackRoutes';
import packageRoutes from './routes/app/packageRoutes';
import paymentRoutes from './routes/app/paymentRoutes';
import questionCategoryRoutes from './routes/app/questionCategoriesRoutes'
import successStoriesRoutes from './routes/app/successStoriesRoutes';
import userBlockRoutes from './routes/app/userBlockRoutes';

//#endregion

const NAMESPACE = 'Server';
const router = express();

const corsOptions = {
  origin: 'https://matrimony-theta.vercel.app',
};

router.use(cors());

router.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://matrimony-theta.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

router.use(cors(corsOptions));

/** Logging the request */
router.use((req, res, next) => {
    /** Log the req */
    logging.info(NAMESPACE, `METHOD: [${req.method}] - URL: [${req.url}] - IP: [${req.socket.remoteAddress}]`);

    res.on('finish', () => {
        /** Log the res */
        logging.info(NAMESPACE, `METHOD: [${req.method}] - URL: [${req.url}] - STATUS: [${res.statusCode}] - IP: [${req.socket.remoteAddress}]`);
    });

    next();
});

/** Parse the body of the request */
router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json({
    limit: "50mb"
}));

/** Rules of our API */
router.use((req, res, next) => {
    // res.header('Access-Control-Allow-Origin', '*');
    // res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization,refreshtoken');

    // if (req.method == 'OPTIONS') {
    //     res.header('Access-Control-Allow-Methods', 'PUT, POST, PATCH, DELETE, GET');
    //     return res.status(200).json({});
    // }

    // Website you wish to allow to connect
    res.header('Access-Control-Allow-Origin', '*');

    // Request methods you wish to allow
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');

    // Request headers you wish to allow
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, refreshtoken');

    next();
});

/** Routes go here */
router.use('/', express.static('apidoc'));
router.use('/content', express.static('content'));
router.use('/sample', sampleRoutes);


//#region Admin
router.use('/api/admin/users', usersRoutes);
router.use('/api/admin/dashboard', dashboardRoutes);
router.use('/api/admin/annualIncome', annualIncomeRoutes);
router.use('/api/admin/appUsers', appUsersRoutes);
router.use('/api/admin/community', communityRoutes);
router.use('/api/admin/diet', dietRoutes);
router.use('/api/admin/education', educationRoutes);
router.use('/api/admin/height', heightRoutes);
router.use('/api/admin/maritalStatus', maritalStatusRoutes);
router.use('/api/admin/occupation', occupationRoutes);
router.use('/api/admin/religion', religionRoutes);
router.use('/api/admin/report', reportRoutes);
router.use('/api/admin/subCommunity', subCommunityRoutes);
router.use('/api/admin/userBlockRequest', userBlockReqRoutes);
router.use('/api/admin/systemFlags', systemFlagsRoutes);
router.use('/api/admin/cities', citiesRoutes);
router.use('/api/admin/states', statesRoutes);
router.use('/api/admin/districts', districtsRoutes);
router.use('/api/admin/employmentType', employmentType);
router.use('/api/admin/successStories', successStory);
router.use('/api/admin/premiumAccountType', premiumAccountType);
router.use('/api/admin/premiumFacility', premiumFacility);
router.use('/api/admin/timeDuration', timeDuration);
router.use('/api/admin/package', userPackage);
router.use('/api/admin/feedback', feedback);
router.use('/api/admin/questionCategories', questionCategoriesRoutes)
//#endregion

//#region App
router.use('/api/app/users', userRoutes);
router.use('/api/app/home', homeRoutes);
router.use('/api/app/agoraToken', agoraToken);
router.use('/api/app/proposals', proposalRoutes);
router.use('/api/app/userBlockRequest', userBlockRequestRoutes);
router.use('/api/app/favourites', userFavouritesRoutes);
router.use('/api/app/notifications', userNotificationsRoutes);
router.use('/api/app/visitors', visitorsRoutes);
router.use('/api/app/userChat', userChatRoutes);
router.use('/api/app/feedback', feedbackRoutes)
router.use('/api/app/package', packageRoutes)
router.use('/api/app/payment', paymentRoutes)
router.use('/api/app/questioncategories', questionCategoryRoutes)
router.use('/api/app/successStories', successStoriesRoutes)
router.use('/api/app/block', userBlockRoutes)
//#endregion

/** Error handling */
router.use((req, res, next) => {
    const error = new Error('Not found');

    res.status(404).json({
        message: error.message
    });
});


router.use((result: any, req: any, res: any, next: any) => {
    if (result.status == 200) {
        res.json({
            status: result.status,
            isDisplayMessage: result.isDisplayMessage,
            message: result.message,
            recordList: result.recordList,
            totalRecords: result.totalRecords
        });
    } else {
        var error = result;
        var trace = null;
        res.status(error.status || 500);
        if (error.error != null) {
            trace = error.error;
        }
        var errorResult = {
            status: error.status,
            isDisplayMessage: error.isDisplayMessage,
            message: error.message,//error.error != undefined && error.error != null ? error.error.message : 'Error object is not available',
            value: error.value,
            error: error
            // error: {
            //     apiName: error.request != undefined && error.request != null ? error.request.url : '',
            //     apiType: error.request != undefined && error.request != null ? error.request.method : '',
            //     fileName: trace != null && trace.length > 0 ? trace[0].getFileName().split('\\').pop() : 'trace is not available',
            //     functionName: trace != null && trace.length > 0 ? trace[0].getFunctionName() : 'trace is not available',
            //     functionErrorMessage:
            //         (error.message != undefined && error.message != null ? error.message : 'Error message is not available') +
            //         ' : ' +
            //         (error.error != undefined && error.error != null ? error.error : 'Error object is not available'),
            //     lineNumber: trace != null && trace.length > 0 ? trace[0].getLineNumber() : 'trace is not available',
            //     typeName: trace != null && trace.length > 0 ? trace[0].getTypeName() : 'trace is not available',
            //     stack: error.stack != undefined && error.stack != null ? error.stack : 'Error stack is not available'
            // }
        };
        // console.log(req.body);
        console.log(errorResult);
        res.json(errorResult);
    }
});

/** Create the Server */
const httpServer = http.createServer(router);
httpServer.listen(config.server.port, () => logging.info(NAMESPACE, `Server is running ${config.server.hostname}:${config.server.port}`));
