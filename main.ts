import GraphicExpressAuthorization from './dist/index';

const users:{[key:string]:string} = {
    "123": "123"
};
// authorization function has to return payload with login or null

const {graphicExpressAuthorization, router, identification} = new GraphicExpressAuthorization({
    authorization: async function authorization(login, password) {
        if(!users[login]) return null;
        if(users[login] === password) return {login, payload: "123", payload2: "123"};
        return null;
    },
    bruteforce:{ // optional
        delay: 5000 // delay between password entry
    },
    htmlPath: undefined, // if you need to use your own html, details below
    jwt: {
        privateKey:require('crypto').randomBytes(512).toString("hex"),
        publicKey: require('crypto').randomBytes(512).toString("hex"),
        payload: ["payload", "payload2"], // allowed payload from authorization function and JWT
        timeToRecreateToken: 600, // Время через которое можно обновить jwt токен
        refreshTokenExpiresIn: '7d', // Время действия refresh token (например, 7 дней)
        genConfig: { // the config used to generate the JWT
            algorithm: "HS256",
            expiresIn: '2h' // время работы jwt токена в милисекундах, можно указывать время типом '7d' - 7 дней
        }
    },
    cookie: { // optional. Settings for the use of cookies
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'strict'
    },
    authPath:"/api/" // have to be the same as api router path
});


import express from 'express';
const app = express();
import cookieParser from 'cookie-parser';

app.use("/api/", router); // have to be the same as authPath

app.get("/enter", cookieParser(), identification, (req,res)=>{ // identification can't be global
    res.json({ message: 'WELCOME'});
});
app.listen(3000, () => {
    console.log(
        ` ┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑` + "\n"+
        ` ┝━━┥ Server is started.` + "\n"+
        ` ┝━━┥ http://localhost:3000/enter` + "\n"+
        ` ┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙`
    );
});