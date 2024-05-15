import { Router, Request, Response, NextFunction, CookieOptions } from 'express';
import { SignOptions, Secret, JwtPayload } from "jsonwebtoken";

interface Config {
    htmlPath?: string;
    bruteforce?: {
        delay?: number;
    };
    authorization: (login: string, password: string) => Promise<AuthData | null> | AuthData | null;
    cookie?: CookieOptions;
    jwt: {
        publicKey?: Secret;
        privateKey: Secret;
        genConfig?: SignOptions;
        payload?: string[];
        timeToRecreateToken?: number;
    };
    authPath?: string;
}

interface AuthData {
    login: string;
    [key: string]: string;
}

class GraphicExpressAuthorization {
    config: Config;
    router: Router;
    graphicExpressAuthorization: GraphicExpressAuthorization;
    GEA: GraphicExpressAuthorization;
    identification: (req: Request, res: Response, next: NextFunction) => Promise<void>;
    lastLoginTime: { [key: string]: number };

    constructor(config: Config);
    createRouter(): Router;
    validateJWT(JWT: string): Promise<null|JwtPayload>;
    generateJWT(login: string, payload?: object): string;
    getPayload(JWT: any): object | undefined;
    useIdentificationFunction(req: Request, res: Response, next: NextFunction): Promise<void>;
}

export = GraphicExpressAuthorization;