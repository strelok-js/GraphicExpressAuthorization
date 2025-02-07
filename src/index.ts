import express, { Request, Response, NextFunction, Router, CookieOptions  } from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import jwt, {JwtPayload, SignOptions} from 'jsonwebtoken';

type JSONValue = string | number | boolean | null | JSONObject | JSONArray | undefined;

interface JSONObject {
    [key: string]: JSONValue;
}

interface JSONArray extends Array<JSONValue> {}

interface JWTConfig {
    privateKey: string;
    publicKey: string;
    genConfig: jwt.SignOptions;
    genPrivateConfig: jwt.SignOptions;
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
    bruteforce?: {[key: string]: number};
    authorization: (login: string, password: string) => Promise<AuthorizationResult | null>;
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
        router.get('/', (req: Request, res: Response) => {
            res.sendFile(this.config.htmlPath ?? __dirname + '/index.html');
        });
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
                    'jwtoken',
                    this.generateJWT(authData.login, payload, this.config.jwt.genConfig),
                    this.config.cookie ?? {
                        path: '/',
                        secure: true,
                        httpOnly: true,
                        sameSite: 'strict',
                    }
                );
                res.cookie(
                    'refreshToken',
                    this.generateJWT(authData.login, payload, this.config.jwt.genPrivateConfig),
                    this.config.cookie ?? {
                        path: '/',
                        secure: true,
                        httpOnly: true,
                        sameSite: 'strict',
                    }
                );

                res.json({ message: 'Identification is successful' }); // ✅ Не возвращаем, просто отправляем ответ
            } catch (error) {
                next(error);
            }
        });
        return router;
    }

    private getPayload(authData: Record<string, any>, additionalPayload: Record<string, any> = {}): Record<string, unknown> {
        if (!this.config.jwt.payload) return additionalPayload;

        const payload: Record<string, JSONObject> = { ...additionalPayload };
        for (const key of this.config.jwt.payload) {
            if (authData[key] !== undefined) {
                payload[key] = authData[key];
            }
        }
        return payload;
    }

/*
    public identificationWithGroup(group: string | string[]) {
        const groups = Array.isArray(group) ? group : [group];
        return async (req: Request, res: Response, next: NextFunction = () => {}) => {
            const JWTGroups = await this.useIdentificationFunction(req, res, (data) => data?.groups ?? []);
            if (!JWTGroups) return;
            if (JWTGroups.some((el: string) => groups.includes(el))) {
                return next(JWTGroups : undefined);
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
        const decodedJWT = token && (await this.validateJwt(token, this.config.jwt.publicKey));
        const refreshToken = req.cookies.refreshToken;
        const decodedRefreshToken = refreshToken && (await this.validateJwt(refreshToken, this.config.jwt.privateKey));

        // Проверка не истек ли jwtToken, если истек создается новый
        const currentTime = Math.floor(Date.now() / 1000);

        if (
            !decodedJWT ||
            this.config.jwt.timeToRecreateToken &&
            decodedJWT.exp &&
            decodedJWT.exp - currentTime < this.config.jwt.timeToRecreateToken ||
            decodedJWT.exp < currentTime
        ) {
            // Проверка на существование и активацию refreshToken
            if (
                !refreshToken ||
                !decodedRefreshToken
            ) {
                return res.redirect(
                    `${req.protocol}://${req.get('host')}${this.config.authPath}?old=${req.originalUrl}`
                );
            }

            res.cookie(
                'jwtoken',
                this.generateJWT(decodedRefreshToken.login, this.getPayload(decodedRefreshToken), this.config.jwt.genConfig),
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

    private async validateJwt(token: string, key: string): Promise<JwtPayload | null> {
        try {
            return jwt.verify(
                token,
                key
            ) as JwtPayload;
        } catch {
            return null;
        }
    }

    private generateJWT(login: string, payload: Record<string, unknown> = {}, config: SignOptions): string {
        return jwt.sign({ login, ...payload }, this.config.jwt.privateKey, config);
    }
}

export default GraphicExpressAuthorization;

