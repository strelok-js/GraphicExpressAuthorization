const { GraphicExpressAuthorization } = require('./dist/index');

const users = {
    "123": "123"
};
// authorization function has to return payload with login or null

const {graphicExpressAuthorization, router, identification} = new GraphicExpressAuthorization({
    authorization: function authorization(login, password) { // funtion to verify password and login
        if(!users[login]) return null;
        if(users[login] === password) return {login, payload: "123", payload2: "123"};
        return null;
    },
    bruteforce:{ // optional
        delay: 5000 // delay between password entry
    },
    htmlPath: null, // if you need to use your own html, details below
    jwt: {
        privateKey:require('crypto').randomBytes(512).toString("hex"),
        payload: ["payload", "payload2"], // allowed payload from authorization function and JWT
        // publicKey: publicKey, // synchronous encryption methods are also supported
        timeToRecreateToken: 600, //10 minutes
        genConfig: { // the config used to generate the JWT
            algorithm: "HS256",
            expiresIn: '2h'
        }
    },
    cookie: { // optional. Settings for the use of cookies
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Strict'
    },
    authPath:"/api/" // have to be the same as api router path
});


const express = require('express');
const app = express();
const cookieParser = require('cookie-parser');

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