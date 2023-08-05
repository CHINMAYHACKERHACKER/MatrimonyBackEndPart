import { NextFunction, Request, Response } from 'express';

const serverHealthCheck = (req: Request, res: Response, next: NextFunction) => {
    // return res.status(200).json({
    //     message: 'pong'
    // });
    let message = "Welcome to our Website! PONG";
    return res.status(200).send(message);
};

export default { serverHealthCheck };