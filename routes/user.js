var nodemailer = require('nodemailer');
var smtpTransport = require('nodemailer-smtp-transport');
var async = require('async');

var crypto = require('crypto');
var User = require('../models/user');
var secret = require('../secret/secret');

module.exports = (app, passport) => {

    app.get('/', (req, res, next) =>{
        
        if(req.session.cookie.originalMaxAge !== null){
            res.redirect('/home');
        }else{
            User.find({}, (err, result) => {
                res.render('index', {title: 'Index || Shop Pet', data:result});
            });
        }
    });

    app.get('/dash1', (req, res) => {
        var errors = req.flash('error');
        res.render('user/dash1', {title: 'Relatórios || Shop Pet', user: req.user});
    });

    app.get('/dash2', (req, res) => {
        var errors = req.flash('error');
        res.render('user/dash2', {title: 'Relatórios || Shop Pet', user: req.user, messages: errors, hasErrors: errors.length > 0});
    });

    app.get('/dash3', (req, res) => {
        var errors = req.flash('error');
        res.render('user/dash3', {title: 'Relatórios || Shop Pet', user: req.user, messages: errors, hasErrors: errors.length > 0});
    });

    app.get('/signup', (req, res) => {
        var errors = req.flash('error');
        res.render('user/signup', {title: 'Cadastre-se || Shop Pet', messages: errors, hasErrors: errors.length > 0});
    });

    app.post('/signup', validate, passport.authenticate('local.signup', {
        successRedirect: '/home',
        failureRedirect: '/signup',
        failureFlash : true
    }));

    app.get('/login', (req, res) => {
        var errors = req.flash('error');
        res.render('user/login', {title: 'Login || Shop Pet', messages: errors, hasErrors: errors.length > 0});
    });
    
    app.post('/login', loginValidation, passport.authenticate('local.login', {
//        successRedirect: '/home',
        failureRedirect: '/login',
        failureFlash : true
    }), (req, res) => {
        if(req.body.rememberme){
            req.session.cookie.maxAge = 30*24*60*60*1000; // 30 dias
        }else{
            req.session.cookie.expires = null;
        }
        res.redirect('/home');
    });    
    
    app.get('/home', (req, res) => {
        res.render('home', {title: 'Home || Shop Pet', user: req.user});
    });
    
    app.get('/forgot', (req, res) => {
        var errors = req.flash('error');
        
        var info = req.flash('info');
        
		res.render('user/forgot', {title: 'Redefinição de Senha', messages: errors, hasErrors: errors.length > 0, info: info, noErrors: info.length > 0});
	});
    
    app.post('/forgot', (req, res, next) => {
        async.waterfall([
            function(callback){
                crypto.randomBytes(20, (err, buf) => {
                    var rand = buf.toString('hex');
                    callback(err, rand);
                });
            },
            
            function(rand, callback){
                User.findOne({'email':req.body.email}, (err, user) => {
                    if(!user){
                        req.flash('error', 'Conta inexistente ou email inválido');
                        return res.redirect('/forgot');
                    }
                    
                    user.passwordResetToken = rand;
                    user.passwordResetExpires = Date.now() + 60*60*1000;
                    
                    user.save((err) => {
                        callback(err, rand, user);
                    });
                })
            },
            
            function(rand, user, callback){
                var smtpTransport = nodemailer.createTransport({
                    service: 'Gmail',
                    auth: {
                        user: secret.auth.user,
                        pass: secret.auth.pass
                    }
                });
                
                var mailOptions = {
                    to: user.email,
                    from: 'Shop Pet '+'<'+secret.auth.user+'>',
                    subject: 'Token de Redefinição de Senha do Aplicativo Shop Pet Renê',
                    text: 'Você solicitou um token para redefinição de senha.  \n\n'+
                        'Por favor, clique no link para concluir o processo: \n\n'+
                        'http://localhost:3000/reset/'+rand+'\n\n'
                };
                
                smtpTransport.sendMail(mailOptions, (err, response) => {
                   req.flash('info', 'Um token de redefinição de senha foi enviado para '+user.email);
                    return callback(err, user);
                });
            }
        ], (err) => {
            if(err){
                return next(err);
            }
            
            res.redirect('/forgot');
        })
    });
    
    app.get('/reset/:token', (req, res) => {
        
        User.findOne({passwordResetToken:req.params.token, passwordResetExpires: {$gt: Date.now()}}, (err, user) => {
            if(!user){
                req.flash('error', 'O token de redefinição de senha expirou ou é inválido. Digite seu e-mail para receber um novo token.');
                return res.redirect('/forgot');
            }
            var errors = req.flash('error');
            var success = req.flash('success');
            
            res.render('user/reset', {title: 'Altere sua Senha', messages: errors, hasErrors: errors.length > 0, success:success, noErrors:success.length > 0});
        });
    });
    
    app.post('/reset/:token', (req, res) => {
        async.waterfall([
            function(callback){
                User.findOne({passwordResetToken:req.params.token, passwordResetExpires: {$gt: Date.now()}}, (err, user) => {
                    if(!user){
                        req.flash('error', 'O token de redefinição de senha expirou ou é inválido. Digite seu e-mail para receber um novo token.');
                        return res.redirect('/forgot');
                    }
                    
                    req.checkBody('password', 'Senha Obrigatória').notEmpty();
                    req.checkBody('password', 'Senha não deve ser menor que 8 caracteres').isLength({min:8});
                    //.matches(/^(?=.*\d)(?=.*[a-z])[0-9a-z]{5,}$/, "i");
                    req.check('password', 'A senha deve conter pelo menos um número.').matches(/\d/);
                    
                    var errors = req.validationErrors();
                    
                    if(req.body.password == req.body.cpassword){
                        if(errors){
                            var messages = [];
                            errors.forEach((error) => {
                                messages.push(error.msg)
                            })
                            
                            var errors = req.flash('error');
                            res.redirect('/reset/'+req.params.token);
                        }else{
                            user.password = user.encryptPassword(req.body.password);
                            user.passwordResetToken = undefined;
                            user.passwordResetExpires = undefined;
                            
                            user.save((err) => {
                                req.flash('success', 'Sua senha foi atualizada com sucesso.');
                                callback(err, user);
                            })
                        }
                    }else{
                        req.flash('error', 'Os campos de senha não conferem.');
                        res.redirect('/reset/'+req.params.token);
                    }
                    
//                    
                });
            },
            
            function(user, callback){
                var smtpTransport = nodemailer.createTransport({
                    service: 'Gmail',
                    auth: {
                        user: secret.auth.user,
                        pass: secret.auth.pass
                    }
                });
                
                var mailOptions = {
                    to: user.email,
                    from: 'Shop Pet '+'<'+secret.auth.user+'>',
                    subject: 'Sua senha foi atualizada.',
                    text: 'Esta é uma confirmação de que você atualizou a senha para '+user.email
                };
                
                smtpTransport.sendMail(mailOptions, (err, response) => {
                    callback(err, user);
                    
                    var error = req.flash('error');
                    var success = req.flash('success');
                    
                    res.render('user/reset', {title: 'Redefinição de senha', messages: error, hasErrors: error.length > 0, success:success, noErrors:success.length > 0});
                });
            }
        ]);
    });
    
    app.get('/logout', (req, res) => {
		req.logout();
		req.session.destroy((err) => {
	        res.redirect('/');
	    });
	})
}


function validate(req, res, next){
   req.checkBody('razao', 'Razão Social obrigatório').notEmpty();
   req.checkBody('nome', 'Nome Fantasia obrigatório').notEmpty();
   req.checkBody('cnpj', 'CNPJ obrigatório').notEmpty();
   req.checkBody('tel', 'Telefone obrigatório').notEmpty();
   req.checkBody('cep', 'CEP obrigatório').notEmpty();   
   req.checkBody('email', 'Email Obrigatório').notEmpty();
   req.checkBody('email', 'Email Invalido').isEmail();
   req.checkBody('password', 'Senha Obrigatória').notEmpty();
   req.checkBody('password', 'Senha não deve ser menor que 8 caracteres').isLength({min:8});
   //.matches(/^(?=.*\d)(?=.*[a-z])[0-9a-z]{5,}$/, "i");
   req.check('password', 'A senha deve conter pelo menos um número.').matches(/\d/);

   var errors = req.validationErrors();

   if(errors){
       var messages = [];
       errors.forEach((error) => {
           messages.push(error.msg);
       });

       req.flash('error', messages);
       res.redirect('/signup');
   }else{
       return next();
   }
}

function loginValidation(req, res, next){
   req.checkBody('email', 'Email obrigatório').notEmpty();
   req.checkBody('email', 'Email inválido').isEmail();
   req.checkBody('password', 'Senha Obrigatória').notEmpty();
  
   var loginErrors = req.validationErrors();

   if(loginErrors){
       var messages = [];
       loginErrors.forEach((error) => {
           messages.push(error.msg);
       });

       req.flash('error', messages);
       res.redirect('/login');
   }else{
       return next();
   }
}