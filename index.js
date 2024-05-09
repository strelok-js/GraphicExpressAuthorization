const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

class GraphicExpressAuthorization {
    constructor(config) {
        this.config = config;
        this.router = this.createRouter();
        this.graphicExpressAuthorization = this.GEA = this;
        this.identification = this.useIdentificationFunction.bind(this);

        this.lastLoginTime = {};
    }
    createRouter() {
        const router = express.Router();
        
        router.use(bodyParser.json());
        router.use(cookieParser());
        router.get('/', (req, res) => {
            res.sendFile(this.config.htmlPath??__dirname+"/index.html");
        });
        router.get('/authentication.js', (req, res) => {
            res.sendFile(__dirname+ "/authentication.js");
        });

        router.post("/setJWT", async (req, res) => {
            if(this.config.bruteforce?.delay) {
                if(Date.now()-(this.lastLoginTime[req.body.login]??0)<=this.config.bruteforce?.delay) 
                    return res.status(429).json({message: "Identification attempt is too frequent"});
                this.lastLoginTime[req.body.login] = Date.now();
            }

            const authData = await this.config.authorization(req.body.login, req.body.password);
            if(!authData) return res.status(401).json({message: "Error identification"});
            else {
                res.cookie('jwtoken', this.generateJWT(authData.login, this.getPayload(authData)), this.config.cookie??{
                    path: '/',
                    secure: true,
                    httpOnly: true,
                    sameSite: 'Strict'
                });
                return res.json({ message: 'Identification is successful'});
            }
        });

        return router;
    }
    validateJWT(JWT) {
        return new Promise((res,rej)=>{
            jwt.verify(JWT, this.config.jwt.publicKey??this.config.jwt.privateKey, (err, decoded)=>{
                if(err) res(null);
                else res(decoded);
            });
        });
    }
    generateJWT(login, payload={}){
        return jwt.sign({ login, ...payload }, this.config.jwt.privateKey, this.config.jwt.genConfig);
    }
    getPayload(JWT) {
        if(!this.config.jwt.payload) return undefined;
        const out = {};
        for (const key of this.config.jwt.payload) out[key] = JWT[key];
        return out;
    }
    async useIdentificationFunction(req, res, next) {
        const JWTDec = req.cookies.jwtoken&&await this.validateJWT(req.cookies.jwtoken);
        if(!JWTDec) return res.redirect(`${req.protocol}://${req.get('host')}`+this.config.authPath+"?old="+req.originalUrl);
        const currentTime = Math.floor(Date.now() / 1000);
        if(
            this.config.jwt.timeToRecreateToken &&
            JWTDec.exp - currentTime < this.config.jwt.timeToRecreateToken
        ) res.cookie('jwtoken', this.generateJWT(JWTDec.login, this.getPayload(JWTDec)), this.config.cookie??{
            path: '/',
            secure: true,
            httpOnly: true,
            sameSite: 'Strict'
        });
        next();
    }
}

module.exports = GraphicExpressAuthorization;