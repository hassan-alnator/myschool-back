const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    email: {
        type: String,
        required: true,
        match: /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/
    },
    password: {
        type: String,
        required: true},
    resources: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Resource'
        }
    ],
    subjects: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Subject'
        }
    ]
});

// export name of model and schema of model
module.exports = mongoose.model('User', userSchema);