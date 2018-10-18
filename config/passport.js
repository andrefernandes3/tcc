var passport = require('passport');
var User = require('../models/user');
var LocalStrategy = require('passport-local').Strategy;
var secret = require('../secret/secret');

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    });
});

passport.use('local.signup', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, (req, email, password, done) => {

    User.findOne({'email':email}, (err, user) => {
        if(err){
            return done(err);
        }

        if(user){
            return done(null, false, req.flash('error', 'Usuário com email já cadastrado.'));
        }

        var newUser = new User();
        newUser.razao = req.body.razao;
        newUser.nome = req.body.nome;
        newUser.cnpj = req.body.cnpj;
        newUser.tel = req.body.tel;
        newUser.cep = req.body.cep;
        newUser.rua = req.body.rua;
        newUser.bairro = req.body.bairro;
        newUser.cidade = req.body.cidade;
        newUser.uf = req.body.uf;
        newUser.email = req.body.email;        
        newUser.password = newUser.encryptPassword(req.body.password);

        newUser.save((err) => {
            return done(null, newUser);
        });
    })
}));

passport.use('local.login', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, (req, email, password, done) => {

    User.findOne({'email':email}, (err, user) => {
        if(err){
            return done(err);
        }
        
        var messages = [];
        
        if(!user || !user.validPassword(password)){
            messages.push('E-mail não existe ou a senha é inválida')
            return done(null, false, req.flash('error', messages));
        }
        
        return done(null, user); 
    });
}));