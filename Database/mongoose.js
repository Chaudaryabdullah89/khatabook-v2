const mongoose = require("mongoose");
const dotenv = require('dotenv');

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://chabdullah:abdullah21@backend.tr2ys.mongodb.net/?retryWrites=true&w=majority&appName=backend";

const connectToDatabase = async () => {
  try {
    await mongoose.connect(MONGODB_URI, {});
    console.log("Connected to MongoDB");
  } catch (err) {
    console.log(err);
  }
};

module.exports = connectToDatabase; 
