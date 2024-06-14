import mongoose from './index.js';

const user = mongoose.Schema({
    firstname: String,
    lastname: String,
    email: String,
    password: String
})

export default mongoose.model("user", user)