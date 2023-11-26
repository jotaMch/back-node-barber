/* imports */
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const bodyParser = require('body-parser') 
const cors = require('cors');
const app = express() 
app.use(cors());

//config JSON response
app.use(express.json())
//config body parser
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); 

//Models
const User = require('../models/User')

//public Route
app.get('/', (req,res) => {
    res.status(200).json({
        msg: "Bem vindo a minha API"
    })
})

//Private Route
app.get("/user/:id", checkToken, async (req, res) => {
    /* const id = req.params.id */

    //check user exits
    const id = req.params.id;
    console.log('ID recebido:', id);

    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(422).json({ msg: 'ID inválido' });
    }
    try {
        const user = await User.findById(id, '-password');
        if (!user) {
            return res.status(404).json({ msg: 'Usuário não encontrado' });
        }
        res.status(200).json({ user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: 'Erro ao  consultar o usuário' });
    }
})

function checkToken(req, res, next) {
    console.log(req.body);
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]
    if(!token) {
        return res.status(401).json({msg: 'Acesso negado!'})
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    } catch(error) {
        res.status(400).json({msg: 'Token invalido!'})
    }
}
//register
app.post('/auth/register', async(req,res) => {
    const {name, email, password, confirmpassword} = req.body
    console.log(req.body);
    console.log('Received registration request:', req.body);


    //validation
    if(!name) {
        return res.status(422).json({
            msg: "O nome é obrigatório!"
        })
    }
    if(!email) {
        return res.status(422).json({
            msg: "O email é obrigatório!"
        })
    }
    if(!password) {
        return res.status(422).json({
            msg: "O password é obrigatório!"
        })
    }
    if(password !== confirmpassword) {
        return res.status(422).json({
            msg: "As senhas não conferem"
        })
    }

    //check if user exist
    const userExists = await User.findOne({email: email})
    
    if(userExists) {
        return res.status(422).json({
            msg: "Por favor, utilize outro e-mail"
        })
    }

    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHas = await bcrypt.hash(password, salt)

    //creat user
    const user = new User({
        name,
        email,
        password: passwordHas,
    })

    try {
        await user.save();
        console.log('User saved successfully:', user);
        res.status(201).json({msg: 'Usuário criado com sucesso!'});
    } catch(error) {
        console.log(error)
        res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'})
    }
})

// Login User
app.post("/auth/login", async (req, res) => {
    const {email, password} = req.body

    if(!email) {
        return res.status(422).json({
            msg: "O email é obrigatório!"
        })
    }
    if(!password) {
        return res.status(422).json({
            msg: "O password é obrigatório!"
        })
    }

    //check if use exists
    const user = await User.findOne({email: email})
    
    if(!user) {
        return res.status(404).json({
            msg: "Usuario não encontrado"
        })
    }

    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)
    if(!checkPassword){
        return res.status(422).json({
            msg: "Senha invalida!"
        })
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id:  user._id
        },
        secret,
        )
        res.status(200).json({
            msg: "Autenticação realizada com sucesso",
            token
        })
    } catch(err) {        
        console.log(error)
        res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'})
    }
})
// Porta
const PORT = process.env.PORT || 3000;

// Credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

// String de Conexão MongoDB
const mongoURI = `mongodb+srv://${encodeURIComponent(dbUser)}:${encodeURIComponent(dbPassword)}@cluster0.itipf2v.mongodb.net/?retryWrites=true&w=majority`;

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Servidor rodando na porta ${PORT}`);
        });
        console.log("Conectou ao banco de dados MongoDB Atlas [Conexão concluida]");
    })
    .catch((err) => console.error(err));





