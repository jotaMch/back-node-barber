const mongoose = require('../src/node_modules/mongoose');

const User = mongoose.model('User', {
    name: String,
    email: String,
    password: String
})
module.exports = User;