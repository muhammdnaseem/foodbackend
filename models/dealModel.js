import mongoose from "mongoose";

const dealSchema = new mongoose.Schema({
    dealtitle: {type: String,required: true},
    dealdescription: {type: String,required: true},
    offpercentage: {type: Number,required: true},
    dealtime: {type: String,required: true},
    dealproduct: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'food',
        required: true
      },

      createdAt: {
        type: Date,
        default: Date.now // Automatically set the current date/time
    }
    
})

const dealModel = mongoose.model.deal || mongoose.model("deal",dealSchema);

export default dealModel;