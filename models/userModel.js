import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name:{type:String, required:true},
    email:{type:String, required:true, unique:true},
    mobile:{type:String, required:false},
    password:{type:String, required:true},
    cartData: {
        type: Object,
        default: {
            items: {}, // Store item quantities here
            selectedSizes: {} // Store selected sizes here
        }
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: String,
    verificationTokenExpiresAt: Date,
    resetPasswordLink: String,
    resetPasswordLinkExpiresAt: Date,
},{minimize:false})

const userModel = mongoose.model.user || mongoose.model("user", userSchema);

export default userModel;