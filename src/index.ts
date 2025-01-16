import express, { Request, Response, NextFunction, Router, CookieOptions  } from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import jwt, { JwtPayload } from 'jsonwebtoken';

type JSONValue = string | number | boolean | null | JSONObject | JSONArray | undefined;

interface JSONObject {
    [key: string]: JSONValue;
}

interface JSONArray extends Array<JSONValue> {}

interface JWTConfig {
    privateKey: string;
    publicKey?: string;
    genConfig?: jwt.SignOptions;
    payload?: string[];
    timeToRecreateToken?: number;
}

interface AuthorizationResult {
    login: string;
    groups?: string[];
    error?: string;
}

interface AuthorizationConfig {
    htmlPath?: string;
    authPath?: string;
    jwt: JWTConfig;
    cookie?: CookieOptions;
    bruteforce?: number;
    authorization: (login: string, password: string) => Promise<AuthorizationResult | null>;
}

interface IdentificationFunction {
    (req: Request, res: Response, next?: NextFunction, noMiddle?: boolean): Promise<void>;
    // withGroup: (group: string | string[]) => (req: Request, res: Response, next?: NextFunction, noMiddle?: boolean) => Promise<void>;
}

export class GraphicExpressAuthorization {
    private config: AuthorizationConfig;
    router: Router;
    lastLoginTime: Record<string, number>;
    graphicExpressAuthorization: this;
    identification: IdentificationFunction;
    GEA: GraphicExpressAuthorization;

    constructor(config: AuthorizationConfig) {
        this.config = config;
        this.router = this.createRouter();
        this.graphicExpressAuthorization = this.GEA = this;
        this.identification = this.useIdentificationFunction.bind(this) as IdentificationFunction;
        // this.identification.withGroup = this.identificationWithGroup.bind(this);

        this.lastLoginTime = {};
    }

    private createRouter(): Router {
        const router = express.Router();

        router.use(bodyParser.json());
        router.use(cookieParser());
        router.get('/', (req: Request, res: Response) => {
            res.sendFile(this.config.htmlPath ?? __dirname + '/index.html');
        });
        router.get('/authentication.js', (req: Request, res: Response) => {
            res.sendFile(__dirname + '/authentication.js');
        });

        router.post('/setJWT', (req: Request, res: Response, next: NextFunction) => {
            (async () => {
                const { login, password } = req.body;
                if (this.config.bruteforce) {
                    if (Date.now() - (this.lastLoginTime[login] ?? 0) <= this.config.bruteforce) {
                        return res.status(429).json({ message: 'Identification attempt is too frequent' });
                    }
                    this.lastLoginTime[login] = Date.now();
                }

                const authData = await this.config.authorization(login, password);
                if (!authData || (authData.error && !authData.login)) {
                    return res.status(401).json({ message: authData?.error ?? 'Error identification' });
                }

                const payload = this.getPayload(authData);
                res.cookie(
                    'jwtoken',
                    this.generateJWT(authData.login, payload),
                    this.config.cookie ?? {
                        path: '/',
                        secure: true,
                        httpOnly: true,
                        sameSite: 'strict',
                    }
                );
                return res.json({ message: 'Identification is successful' });
            })().catch(next);
        });

        return router;
    }

    private validateJWT(token: string): Promise<JwtPayload | null> {
        return new Promise((resolve) => {
            jwt.verify(
                token,
                this.config.jwt.publicKey ?? this.config.jwt.privateKey,
                (err, decoded) => {
                    if (err) resolve(null);
                    else resolve(decoded as JwtPayload);
                }
            );
        });
    }

    private generateJWT(login: string, payload: Record<string, unknown> = {}): string {
        const tokenPayload = { login, ...payload };
        return jwt.sign(tokenPayload, this.config.jwt.privateKey, this.config.jwt.genConfig);
    }

    private getPayload(authData: Record<string, any>, additionalPayload: Record<string, any> = {}): Record<string, unknown> {
        console.log(authData);
        console.log(authData);
        if (!this.config.jwt.payload) return additionalPayload;

        const payload: Record<string, JSONObject> = { ...additionalPayload };
        for (const key of this.config.jwt.payload) {
            if (authData[key] !== undefined) {
                payload[key] = authData[key];
            }
        }
        console.log(authData);
        return payload;
    }
/*
    public identificationWithGroup(group: string | string[]) {
        const groups = Array.isArray(group) ? group : [group];
        return async (req: Request, res: Response, next: NextFunction = () => {}, noMiddle = false) => {
            const JWTGroups = await this.useIdentificationFunction(req, res, (data) => data?.groups ?? []);
            if (!JWTGroups) return;
            if (JWTGroups.some((el: string) => groups.includes(el))) {
                return next(noMiddle ? JWTGroups : undefined);
            }
            return res.redirect(
                `${req.protocol}://${req.get('host')}${this.config.authPath}?old=${req.originalUrl}`
            );
        };
    }
*/
    public async useIdentificationFunction(
        req: Request,
        res: Response,
        next: NextFunction = () => {},
    ): Promise<void> {
        const token = req.cookies.jwtoken;
        const decodedJWT = token && (await this.validateJWT(token));
        if (!decodedJWT) {
            return res.redirect(
                `${req.protocol}://${req.get('host')}${this.config.authPath}?old=${req.originalUrl}`
            );
        }
        const currentTime = Math.floor(Date.now() / 1000);
        if (
            this.config.jwt.timeToRecreateToken &&
            decodedJWT.exp &&
            decodedJWT.exp - currentTime < this.config.jwt.timeToRecreateToken
        ) {
            res.cookie(
                'jwtoken',
                this.generateJWT(decodedJWT.login, this.getPayload(decodedJWT)),
                this.config.cookie ?? {
                    path: '/',
                    secure: true,
                    httpOnly: true,
                    sameSite: 'strict',
                }
            );
        }
        return next();
    }
}

export default GraphicExpressAuthorization;

