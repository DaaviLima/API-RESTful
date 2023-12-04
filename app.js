/*importações*/
require('dontenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jwt');

const app  = express();

//Configurando json
app.use(express.json()); 

const User = require('./models/User');

app.get('/', (req, res) => {
    res.status(200).json({msg:"Bem vindo"});
});

//rota privada
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id;
    const user = await User.findById(id,'-senha');
    if(!user){
        return res.status(404).json({msg:'Usuario não encontrado'});
    }
    res.status(200).json({user});
});

function checkToken(req, res, next){
    const authHeader = req.headers['Autorizado'];
    const token = authHeader && authHeader.split(" ")[1];
    if(!token){
        return res.status(401).json({msg:'Acesso negado'});
    }
    try{
        const secret = process.env.secret;
        jwt.verify(token, secret);
        next();
    } catch(err){
        res.status(400).json({msg:'Token inválido'});
    }
}

//Regristrar usuario
app.post('/auth/register', async (req, res) => {
    const { nome, email, senha, confirmasenha, telefone } = req.body;
    if(!nome){
        return res.status(422).json({msg:"Faltou colocar o seu nome "});
    }
    if(!email){
        return res.status(422).json({msg:"Faltou colocar o seu email "});
    }
    if(!senha){
        return res.status(422).json({msg:"Faltou colocar a sua senha"}); 
    }
    if(!telefone){
        return res.status(422).json({msg:"Faltou colocar o seu telefone"}); 
    }
    if(senha !== confirmasenha){
        return res.status(422).json({msg:"Senha inválida"});
    }

    //checando email
    const userExists = await User.findOne({email:email});
    if(userExists) {
        return res.status(422).json({msg:'Email ja cadastrado'});
    }

    //checando senha 
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(senha, salt);

    // criando usuario
    const usuario = new User({
        nome,
        email,
        senha: passwordHash,
        telefone
    });

    try{
        await usuario.save();
        res.status(200).json({msg:'Conta criada com sucesso'});
    } catch(err){
        res.status(500).json({
            msg:'Aconteceu um erro, tente novamente mais tarde'
        });
    }
});

//login do usuario
app.post("/auth/user", async (req, res) =>{
    const { email, senha } = req.body;
    if(!email){
        return res.status(422).json({msg:"Faltou colocar o seu email "});
    }
    if(!senha){
        return res.status(422).json({msg:"Faltou colocar a sua senha"}); 
    }

    //checando usuario
    const user = await User.findOne({email: email});
    if(!user){
        return res.status(404).json({msg:'Usuário não encontrado'});
    }

    //checando senha
    const checkPassword = await bcrypt.compare(senha, user.password);
    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha inválida" });
    }

    try{
        const secret = process.env.SECRET;
        const token = jwt.sign(
            {
                id:user._id,
            },
            secret
        );
        res.status(200).json({msg:'Autenticação realizada com sucesso', token});
    } catch(err){
        console.log(err);
        res.status(500).json({ msg: err });
    }
});

const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
.connect(`mongodb+srv://${dbUser}${dbPassword}@cluster0.hmvvs4l.mongodb.net/?retryWrites=true&w=majority`)
.then(() => {
    app.listen(3000);
    console.log('Conectou ao banco');
})
.catch((err) => console.log(err));
