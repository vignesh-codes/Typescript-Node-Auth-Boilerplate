import express from 'express';

import { UserDatabase } from '../../db/users';
import { authentication, random } from '../../helpers'
import { generateJwt } from '../../middlewares/v2/jwt';
import { Logger } from '../../loggers/logger'
export class V2AuthController {
    private static userDB = UserDatabase.getInstance();

    public static v2login = async (req: express.Request, res: express.Response) => {
        try {
            const { email, password } = req.body;
            if (!email || !password) {
                return res.sendStatus(400)
            }
            const user = await V2AuthController.userDB.getUserByEmail(email).select("+authentication.salt +authentication.password");

            if (!user) {
                return res.sendStatus(400)
            }

            const expectedHash = authentication(user.authentication.salt, password);
            if (user.authentication.password != expectedHash) {
                return res.sendStatus(401)
            }
            let jwtToken = ""
            try {
                jwtToken = await generateJwt(user);
            } catch (error) {
                Logger.Error("Error generating JWT token:" + error.toString());
                return res.sendStatus(401)
            }
            let userObj = user.toObject()
            userObj.authentication.jwtToken = jwtToken;
            return res.status(200).json(userObj).end()

        } catch (error) {
            Logger.Error(error.toString())
            return res.sendStatus(400)
        }
    }


    public static v2register = async (req: express.Request, res: express.Response) => {
        try {
            const { email, password, username } = req.body;

            if (!email || !password || !username) {
                return res.sendStatus(400);
            };

            const existingUser = await V2AuthController.userDB.getUserByEmail(email);
            if (existingUser) {
                return res.sendStatus(400);
            };

            const salt = random();
            const user = await V2AuthController.userDB.createUser({
                email,
                username,
                authentication: {
                    salt,
                    password: authentication(salt, password)
                },
            });

            return res.status(200).json(user).end()

        } catch (error) {
            Logger.Error(error.toString());
            return res.sendStatus(400);
        }
    }
}
