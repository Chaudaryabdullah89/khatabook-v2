const mongoose = require("mongoose")

const userschema = new mongoose.Schema({
    username : {
        type : String,
        required : true,
        unique : true,
    },
    fullname : {
        type : String,
        required : true,
    },
    password : {
        type : String,
        
    },
    email : {
        type : String,
        required : true,
        unique : true,
    }
}, { timestamps: true })

const user = mongoose.model("user" , userschema)

module.exports = user;