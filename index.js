const express = require('express');
require('dotenv/config');
const { urlencoded } = require('body-parser');
const cookieParser = require('cookie-parser');
const { hash, compare } = require('bcryptjs');
const { verify } = require('jsonwebtoken');
const cors = require('cors');
const { DB } = require('./src/DB');
const { isAuth } = require('./src/isAuth');
const {
    createAccessToken,
    createRefreshToken,
    sendAccessToken,
    sendRefreshToken
} = require('./tokens');

const app = express();

// express middleware
app.use(express.json());
app.use(express.urlencoded({extended: true}));

//cors middleware
app.use(cors({
    origin: "http://localhost:3000",
    credentials: true
}));

//cookieParser middleware
app.use(cookieParser());

// 1. Register a user.
// 2. log in a user.
// 3. log out a user.
// 4. protected route
// 5. refreshtoken

// 1. Register a user
app.post('/register', async (req, res) => {
    //get the email and password from req body
    const { email, password } = req.body;
    //check if thr user already exists
    const user = DB.find(user => user.email === email);

    try{
        if(user) throw new Error("User already exists");
        const hashedPassword = await hash(password, 10);
        DB.push({
            id: DB.length,
            email,
            password: hashedPassword
        });
        res.send({
            message: "User registered successfully"
        })
    }
    catch (err) {
        res.send({
            message: `${err.message}`
        });
    }
});

// log in a user 
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try{
        const user = DB.find(user => user.email === email);
        if(!user) throw new Error("User not found");
        
        //check the password
        const valid = await compare(password, user.password);
        if(!valid) throw new Error("Password not correct");
        // --->> if user found then send back the token 
        // create the tokens
        const accessToken = createAccessToken(user.id);
        const refreshToken = createRefreshToken(user.id);

        //put the refresh token in the database
        user.refreshToken = refreshToken;
        //send the tokens ... access -> direct ||| refresh -> through a cookie

        console.log(DB);

        sendRefreshToken(res, refreshToken);
        sendAccessToken(req, res, accessToken);
    }
    catch (err) {
        res.send({
            message: `${err.message}`
        });
    }
});

//log out a user
app.post('/logout', (req, res) => {
    res.clearCookie('refreshToken', {path: '/refresh-token'});
    return res.send({
        message: "logged out"
    });
});


//protected route
app.post('/protected', (req, res) => {
    try {
        // get verified user id
        const userId = isAuth(req);
        if(userId !== null){
            res.send({
                message: "This data is protected"
            })
        } 
    } catch (err) {
        res.send({
            error: `${err.message}`
        })
    }
})


//get a new access token with a new refresh token
app.post('/refresh-token', (req, res) => {
    const token = req.cookies.refreshToken; 
    //if no token
    if(!token) return res.send({ accessToken: ''});
    //if token ... verify
    let payload = null;
    try {
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET); 
    } catch (err) {
        res.send({
            accessToken: ''
        });
    }
    //token valid, check if user exists
    const user = DB.find(user => user.id === payload.userId);
    if(!user) return res.send({accessToken: ''});

    //user exists, check if refresh token exists on user
    if(user.refreshToken !== token) {
        return res.send({
            accessToken: ''
        })
    }
    //token exists, create new refresh and access token
    const accessToken = createAccessToken(user.id);
    const refreshToken = createRefreshToken(user.id);
    user.refreshToken = refreshToken;

    // good to go, send new refresh token and accesstokenn

    sendRefreshToken(res, refreshToken);
    return res.send({
        accessToken
    });
});

app.listen(process.env.PORT, () => {
    console.log(`server listening on ${process.env.PORT}`);
})