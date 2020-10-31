const express = require('express');
const bcrypt = require('bcrypt');

const app = express();

app.use(express.json());

const users = [];

app.get('/api/v1/users', (req,res) => {
    res.json(users)
})

app.post('/api/v1/register', async (req,res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        console.log(hashedPassword);
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
            res.status(200).send("Login sucessful");
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