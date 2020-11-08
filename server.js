const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

require('dotenv').config({path: './config/.env'});

const app = express();

app.use(express.json());

const users = [];

const authenticateToken = (req,res,next) => {
    const authHeader = req.header('authorization');
    const token = authHeader.split(' ')[1]
    if (!token) return res.status(401).json({error: 'No token given'})
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if(err) return res.status(401).json({error: 'Invalid Token'});

        // console.log(user)
        req.user = user;
        next();
    })
}

//Gets the specific user from the header token
app.get('/api/v1/users', authenticateToken, (req,res) => {
    const user = users.find(user => user.username === req.user.name)
    if (user){
        res.status(201).json({message: 'User Found', user: user})
    }
    else{
        res.status(401).json({message: 'Invalid user'})
    }
})

app.post('/api/v1/register', async (req,res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        // console.log(hashedPassword);
        const user = {
            username: req.body.name,
            password: hashedPassword
        }
        users.push(user);
        res.status(200).send();
    }catch{
        res.status(500).send("something went wrong");
    }
})

app.post('/api/v1/login', async (req,res) => {
    const user = users.find((user) => user.username == req.body.name)
    if (user == null){
        res.status(404).send("User does not exists")
    }
    try{
        if ( await bcrypt.compare(req.body.password, user.password)){
            const userDoc = {name: user.username}
            const accesstoken = jwt.sign(userDoc, process.env.ACCESS_TOKEN_SECRET, {expiresIn: 24*3*60*60});
            res.status(200).json({message: 'Login Sucessfull', accessToken: accesstoken});
        }
        else{
            res.send("Password Incorrect");
        }
    }catch{
        res.status(500).send("something went wrong");
    }
})

app.listen(3001, () => {
    console.log('Server started at port 3001')
})