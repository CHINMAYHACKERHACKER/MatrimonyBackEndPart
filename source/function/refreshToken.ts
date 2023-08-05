import config from '../config/config';
import logging from '../config/logging';
const { uuid } = require('uuidv4');

const NAMESPACE = 'Refresh Token';

const createRefreshToken = async(userId: number) => {
    try {
        logging.info(NAMESPACE, `Creating Refresh Token`);
        
        let expiredDate = new Date();
        expiredDate.setSeconds(expiredDate.getSeconds() + Number(config.server.token.refreshExpirationTime));

        let _token = uuid();

        let refreshToken: any = {
            "token": _token,
            "userId": userId,
            "expireAt": expiredDate,
        };
        return refreshToken;

    } catch (error:any) {
        logging.error(NAMESPACE, error.message, error);
        return error;
    }
}

export default createRefreshToken;