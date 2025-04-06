const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const transactionSchema = new mongoose.Schema({
    description: {
        type: String,
        required: true
    },
    amount: {
        type: Number,
        required: true
    },
    type: {
        type: String,
        enum: ['credit', 'debit'],
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    }
});

const hisabSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    isEncrypted: {
        type: Boolean,
        default: false
    },
    passcode: {
        type: String,
        required: function() {
            return this.isEncrypted;
        }
    },
    isShareable: {
        type: Boolean,
        default: false
    },
    shareToken: {
        type: String,
        unique: true,
        sparse: true
    },
    sharedWith: [{
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        accessLevel: {
            type: String,
            enum: ['view', 'edit'],
            default: 'view'
        }
    }],
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    date: {
        type: Date,
        default: new Date(),
    },
    transactions: [transactionSchema]
    
}, { timestamps: true });

hisabSchema.pre('save', async function(next) {
    if (this.isEncrypted && this.isModified('passcode')) {
        const salt = await bcrypt.genSalt(10);
        this.passcode = await bcrypt.hash(this.passcode, salt);
    }
    
    // Generate share token if hisab is shareable and token doesn't exist
    if (this.isShareable && !this.shareToken) {
        this.shareToken = crypto.randomBytes(16).toString('hex');
    }
    
    next();
});

hisabSchema.methods.verifyPasscode = async function(passcode) {
    if (!this.isEncrypted) return true;
    return await bcrypt.compare(passcode, this.passcode);
};

module.exports = mongoose.model('Hisab', hisabSchema); 