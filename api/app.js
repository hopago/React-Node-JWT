const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const cors = require("cors");

app.use(express.json());
app.use(cors());

const users = [
    {
        id: "1",
        username: "Ho",
        password: "Ho0712",
        isAdmin: true,
    },
    {
        id: "2",
        username: "Hopa",
        password: "Hopa0712",
        isAdmin: false,
    },
];

let refreshTokens = [];

app.post("/api/refresh", (req, res) => {
    
    //take refresh token from the user
    const refreshToken = req.body.token;

    //send error
    if(!refreshToken) return res.status(401).json("You are not authenticated!");
    if(!refreshTokens.includes(refreshToken)) {
        return res.status(403).json("Refresh Token is not valid!");
    }

    //create new access token, refresh token and send to user
    jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {

        err && console.log(err);
        refreshTokens = refreshTokens.filter(token => token !== refreshToken);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        refreshTokens.push(newRefreshToken);

        res.status(200).json({accessToken: newAccessToken, refreshToken: newRefreshToken});

    });

});

const generateAccessToken = (user) => {

    //Generate an access token
    return jwt.sign(
        { id: user.id, isAdmin: user.isAdmin },
        "mySecretKey",
        { expiresIn: "5s" }
    );

}

const generateRefreshToken = (user) => {

    //Generate an refresh token
    return jwt.sign(
            
        { id: user.id, isAdmin: user.isAdmin },
        "myRefreshSecretKey"

    );

};

app.post("/api/login", (req, res) => {

    const { username, password } = req.body;

    const user = users.find(u => {
        return u.username === username && u.password === password;
    });

    if(user) {

        //Generate an access token
        const accessToken = generateAccessToken(user);

        //create refresh token
        const refreshToken = generateRefreshToken(user);

        refreshTokens.push(refreshToken);

        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        });

    } else {
        res.status(400).json("Wrong ID OR PW");
    }

});

const verify = (req, res, next) => {

    const authHeader = req.headers.authorization;

    if(authHeader) {

        const token = authHeader.split(" ")[1];

        jwt.verify(token, "mySecretKey", (err, user) => {

            if(err) {
                return res.status(403).json("Not valid token");
            }

            req.user = user;

            next();

        });

    } else {
        res.status(401).json("Not Authenticated");
    }

};

app.post("/api/logout", verify, (req, res) => {

    const refreshToken = req.body.token;

    refreshTokens = refreshTokens.filter(token => token !== refreshToken);

    res.status(200).json("Logout");

});

app.delete("/api/users/:userId", verify, (req, res) => {

    if(req.user.id === req.params.userId || req.user.isAdmin) {
        res.status(200).json("User has been deleted");
    } else {
        res.status(403).json("Not Allowed Way");
    }

});

app.listen(8000, () => {
    console.log("Backend Ready");
});