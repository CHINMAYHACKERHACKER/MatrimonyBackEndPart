import jwt from 'jsonwebtoken';
import config from '../config/config';
import logging from '../config/logging';

const NAMESPACE = 'Auth';

const signJWT = async (user: any) => {
    logging.info(NAMESPACE, `Attempting to sign token for ${user.id}`);

    try {
        let data = await jwt.sign({
            userId: user.id
        },
        config.server.token.secret,
        {
            issuer: config.server.token.issuer,
            algorithm: 'HS256',
            expiresIn: Number(config.server.token.expireTime)
        });
        return { "token": data };
    } catch (error: any) {
        logging.error(NAMESPACE, error.message, error);
        return error;
    }
};

export default signJWT;