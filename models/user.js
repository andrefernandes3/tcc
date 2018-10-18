var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

var userSchema = mongoose.Schema({
    razao: {type: String, required: true},
    nome: {type: String, required: true},
    cnpj: {type: String, required: true},
    tel: {type: String, required: true},   
    email: {type: String, required: true},
    cep: {type: String, required: true},
    rua: {type: String},
    bairro: {type: String},
    cidade: {type: String},
    uf: {type: String},
    email: {type: String, required: true},
    password: {type: String},    
    passwordResetToken: {type: String, default: ''},
    passwordResetExpires: {type: Date, default: Date.now},
    tokens: Array
});

userSchema.methods.encryptPassword = (password) => {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(10), null);
}
//compara as senhas
userSchema.methods.validPassword = function(password) {
    return bcrypt.compareSync(password, this.password);
};

module.exports = mongoose.model('User', userSchema);