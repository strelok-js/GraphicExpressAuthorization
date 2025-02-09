import { Request, Response, NextFunction, Router, CookieOptions } from 'express';
import jwt from 'jsonwebtoken';
type JSONValue = string | number | boolean | null | JSONObject | JSONArray | undefined;
interface JSONObject {
    [key: string]: JSONValue;
}
interface JSONArray extends Array<JSONValue> {
}
interface JWTConfig {
    privateKey: string;
    publicKey?: string;
    genConfig: jwt.SignOptions;
    genPrivateConfig: jwt.SignOptions;
    payload?: string[];
}
interface AuthorizationConfig {
    htmlPath?: string;
    authPath?: string;
    jwt: JWTConfig;
    cookie?: CookieOptions;
    bruteforce?: {
        [key: string]: number;
    };
    authorization: (login: string, password: string) => Promise<JSONObject | null> | JSONObject | null;
}
export declare class GraphicExpressAuthorization {
    private config;
    router: Router;
    lastLoginTime: Record<string, number>;
    graphicExpressAuthorization: this;
    identification: (req: Request, res: Response, next?: NextFunction) => Promise<void>;
    GEA: GraphicExpressAuthorization;
    constructor(config: AuthorizationConfig);
    private createRouter;
    getPayload(JWT: JSONObject): JSONObject | undefined;
    useIdentificationFunction(req: Request, res: Response, next?: NextFunction): Promise<void>;
    private useRefreshToken;
    private validateJwt;
    private generateJWT;
}
export default GraphicExpressAuthorization;
