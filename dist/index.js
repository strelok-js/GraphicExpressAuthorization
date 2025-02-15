"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GraphicExpressAuthorization = void 0;
const express_1 = __importDefault(require("express"));
const body_parser_1 = __importDefault(require("body-parser"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
class GraphicExpressAuthorization {
    config;
    router;
    lastLoginTime;
    graphicExpressAuthorization;
    identification;
    GEA;
    constructor(config) {
        this.config = config;
        this.router = this.createRouter();
        this.graphicExpressAuthorization = this.GEA = this;
        this.identification = this.useIdentificationFunction.bind(this);
        // this.identification.withGroup = this.identificationWithGroup.bind(this);
        this.lastLoginTime = {};
    }
    createRouter() {
        const router = express_1.default.Router();
        router.use(body_parser_1.default.json());
        router.use((0, cookie_parser_1.default)());
        router.get('/authentication.js', (req, res) => {
            res.sendFile(__dirname + '/authentication.js');
        });
        router.post('/setJWT', async (req, res, next) => {
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
                res.cookie(this.config.jwtCookie?.cookieName ?? 'jwtoken', this.generateJWT(payload, this.config.jwt.genConfig), this.config.jwtCookie ?? {
                    path: '/',
                    secure: true,
                    httpOnly: true,
                    sameSite: 'strict',
                });
                res.cookie(this.config.refreshCookie?.cookieName ?? 'refresh.jwtoken', this.generateJWT(payload, this.config.jwt.genPrivateConfig), this.config.refreshCookie ?? {
                    path: '/',
                    secure: true,
                    httpOnly: true,
                    sameSite: 'strict',
                });
                res.json({ message: 'Identification is successful' });
            }
            catch (error) {
                next(error);
            }
        });
        router.use('/', this.useRefreshToken.bind(this), (req, res) => {
            res.sendFile(this.config.htmlPath ?? __dirname + '/index.html');
        });
        return router;
    }
    getPayload(JWT) {
        if (!this.config.jwt.payload)
            return undefined;
        const out = {};
        for (const key of this.config.jwt.payload)
            out[key] = JWT[key];
        return out;
    }
    async useIdentificationFunction(req, res, next = () => { }) {
        const token = req.cookies[this.config.jwtCookie?.cookieName ?? 'jwtoken'];
        const decodedJWT = token && (await this.validateJwt(token, this.config.jwt.publicKey || this.config.jwt.privateKey));
        if (decodedJWT)
            return next();
        res.status(307)
            .set('Location', `${req.protocol}://${req.get('host')}${this.config.authPath}?old=${req.originalUrl}`)
            .end();
    }
    async useRefreshToken(req, res, next = () => { }) {
        const token = req.cookies[this.config.refreshCookie?.cookieName ?? 'refresh.jwtoken'];
        const decodedJWT = token && (await this.validateJwt(token, this.config.jwt.publicKey || this.config.jwt.privateKey));
        if (!decodedJWT)
            return next();
        res.cookie(this.config.jwtCookie?.cookieName ?? 'jwtoken', this.generateJWT(this.getPayload(decodedJWT), this.config.jwt.genConfig), this.config.refreshCookie ?? {
            path: '/',
            secure: true,
            httpOnly: true,
            sameSite: 'strict',
        });
        if (!req.query.old && typeof req.query.old !== 'string') {
            res.status(400).json({ error: 'oldPath is not define' });
            return;
        }
        res.status(307)
            .set('Location', req.query.old)
            .end();
    }
    validateJwt(token, key) {
        return new Promise((resolve, reject) => {
            jsonwebtoken_1.default.verify(token, key, (err, decoded) => {
                if (err) {
                    resolve(null);
                }
                resolve(decoded);
            });
        });
    }
    generateJWT(payload = {}, config) {
        return jsonwebtoken_1.default.sign(payload, this.config.jwt.privateKey, config);
    }
}
exports.GraphicExpressAuthorization = GraphicExpressAuthorization;
exports.default = GraphicExpressAuthorization;
