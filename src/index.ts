import express, { Request, Response, NextFunction, Router, CookieOptions, request } from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import jwt, { JwtPayload, SignOptions } from 'jsonwebtoken';

type JSONValue = string | number | boolean | null | JSONObject | JSONArray | undefined;

interface JSONObject {
    [key: string]: JSONValue;
}

interface JSONArray extends Array<JSONValue> {}

interface JWTConfig {
    privateKey: string;
    publicKey?: string;
    genConfig: jwt.SignOptions;
    genPrivateConfig: jwt.SignOptions;
    payload?: string[];
}

interface GEACookieOptions extends CookieOptions {
    cookieName?: string;
}

interface AuthorizationConfig {
    htmlPath?: string;
    authPath?: string;
    jwt: JWTConfig;
    jwtCookie?: GEACookieOptions;
    refreshCookie?: GEACookieOptions;
    bruteforce?: { [key: string]: number };
    authorization: (login: string, password: string) => Promise<JSONObject | null> | JSONObject | null;
}

export class GraphicExpressAuthorization {
    private config: AuthorizationConfig;
    router: Router;
    lastLoginTime: Record<string, number>;
    graphicExpressAuthorization: this;
    identification: (req: Request, res: Response, next?: NextFunction) => Promise<void>;
    GEA: GraphicExpressAuthorization;

    constructor(config: AuthorizationConfig) {
        this.config = config;
        this.router = this.createRouter();
        this.graphicExpressAuthorization = this.GEA = this;
        this.identification = this.useIdentificationFunction.bind(this);
        // this.identification.withGroup = this.identificationWithGroup.bind(this);

        this.lastLoginTime = {};
    }

    private createRouter(): Router {
        const router = express.Router();

        router.use(bodyParser.json());
        router.use(cookieParser());
        router.get('/authentication.js', (req: Request, res: Response) => {
            res.sendFile(__dirname + '/authentication.js');
        });

        router.post('/setJWT', async (req: Request, res: Response, next: NextFunction) => {
            try {
                const { login, password } = req.body;

                if (this.config.bruteforce) {
                    if (Date.now() - (this.lastLoginTime[login] ?? 0) <= this.config.bruteforce.delay) {
                        res.status(429).json({ message: 'Identification attempt is too frequent' });
                        return;
                    }
                    this.lastLoginTime[login] = Date.now();
                }

                const authData = await this.config.authorization(login, password);
                if (!authData || (authData.error && !authData.login)) {
                    res.status(401).json({ message: authData?.error ?? 'Error identification' });
                    return;
                }

                const payload = this.getPayload(authData);
                res.cookie(
                    this.config.jwtCookie?.cookieName ?? 'jwtoken',
                    this.generateJWT(payload, this.config.jwt.genConfig),
                    this.config.jwtCookie ?? {
                        path: '/',
                        secure: true,
                        httpOnly: true,
                        sameSite: 'strict',
                    },
                );
                res.cookie(
                    this.config.refreshCookie?.cookieName ?? 'refresh.jwtoken',
                    this.generateJWT(payload, this.config.jwt.genPrivateConfig),
                    this.config.refreshCookie ?? {
                        path: '/',
                        secure: true,
                        httpOnly: true,
                        sameSite: 'strict',
                    },
                );

                res.json({ message: 'Identification is successful' });
            } catch (error) {
                next(error);
            }
        });

        router.use('/', this.useRefreshToken.bind(this), (req: Request, res: Response) => {
            res.sendFile(this.config.htmlPath ?? __dirname + '/index.html');
        });

        return router;
    }

    getPayload(JWT: JSONObject) {
        if (!this.config.jwt.payload) return undefined;
        const out: JSONObject = {};
        for (const key of this.config.jwt.payload) out[key] = JWT[key];
        return out;
    }

    public async useIdentificationFunction(req: Request, res: Response, next: NextFunction = () => {}): Promise<void> {
        const token = req.cookies.jwtoken;
        const decodedJWT = token && (await this.validateJwt(token, this.config.jwt.publicKey || this.config.jwt.privateKey));

        if (decodedJWT) return next();
        res.status(307)
            .set('Location', `${req.protocol}://${req.get('host')}${this.config.authPath}?old=${req.originalUrl}`)
            .end();
    }

    private async useRefreshToken(req: Request, res: Response, next: NextFunction = () => {}): Promise<void> {
        const token = req.cookies[this.config.refreshCookie?.cookieName ?? 'refresh.jwtoken'];
        const decodedJWT = token && (await this.validateJwt(token, this.config.jwt.publicKey || this.config.jwt.privateKey));

        if (!decodedJWT) return next();

        res.cookie(
            this.config.jwtCookie?.cookieName ?? 'jwtoken',
            this.generateJWT(this.getPayload(decodedJWT), this.config.jwt.genConfig),
            this.config.refreshCookie ?? {
                path: '/',
                secure: true,
                httpOnly: true,
                sameSite: 'strict',
            },
        );

        if (!req.query.old && typeof req.query.old !== 'string') {
            res.status(400).json({ error: 'oldPath is not define' });
            return;
        }

        res.status(307)
            .set('Location', req.query.old as string)
            .end();
    }

    private validateJwt(token: string, key: string): Promise<JwtPayload | null> {
        return new Promise((resolve, reject) => {
            jwt.verify(token, key, (err, decoded) => {
                if (err) {
                    resolve(null);
                }
                resolve(decoded as JwtPayload);
            });
        });
    }

    private generateJWT(payload: JSONObject | undefined = {}, config: SignOptions): string {
        return jwt.sign(payload, this.config.jwt.privateKey, config);
    }
}

export default GraphicExpressAuthorization;
