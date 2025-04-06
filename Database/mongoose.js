const mongoose = require("mongoose");
const dotenv = require('dotenv');

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://chabdullah:abdullah21@backend.tr2ys.mongodb.net/?retryWrites=true&w=majority&appName=backend";

// Create a cached connection variable
let cachedConnection = null;

const connectToDatabase = async () => {
  // If connection exists, use it
  if (cachedConnection) {
    console.log("Using cached MongoDB connection");
    return cachedConnection;
  }

  try {
    // Connection options optimized for serverless
    const connection = await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
      socketTimeoutMS: 45000, // Close sockets after 45s
    });
    
    console.log("Connected to MongoDB");
    cachedConnection = connection;
    return connection;
  } catch (err) {
    console.error("MongoDB connection error:", err);
    throw err;
  }
};

module.exports = connectToDatabase; 
