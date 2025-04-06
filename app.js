const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const connectToDatabase = require("./Database/mongoose");
const user = require("./Models/user.model");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const Hisab = require("./Models/hisab.model");
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

// Initialize database connection only once
const initializeApp = async () => {
  try {
    await connectToDatabase();
    console.log("Database initialized");
  } catch (error) {
    console.error("Failed to initialize database:", error);
  }
};

// In development, immediately initialize
if (process.env.NODE_ENV !== 'production') {
  initializeApp();
} else {
  // In production (Vercel), initialize on first request
  app.use(async (req, res, next) => {
    try {
      if (!global.mongooseInitialized) {
        await connectToDatabase();
        global.mongooseInitialized = true;
      }
      next();
    } catch (error) {
      console.error("Database connection error:", error);
      res.status(500).send("Database connection error");
    }
  });
}

// middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-secret-key",
    resave: false,
    saveUninitialized: true,
    cookie: { 
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', // Helps with CSRF protection
      httpOnly: true, // Helps protect against XSS attacks
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
  })
);

// Set up cookie parser with same options
app.use(cookieParser(process.env.SESSION_SECRET || "your-secret-key"));

// Trust the Vercel proxy to properly set secure cookies
app.set('trust proxy', 1);

function isloggedin(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.render("login", {
      error: "You have to login first",
    });
  }
  const decoded = jwt.verify(token, process.env.JWT_SECRET || "secretkey");
  req.user = decoded;
  // console.log(req.user);
  next();
}

app.set("views", path.join(__dirname, "VIews"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// all get routes

app.get("/", (req, res) => {
  const token = req.cookies.token;
  let isLoggedIn = false;
  if (token) {
    try {
      jwt.verify(token, process.env.JWT_SECRET || "secretkey");
      isLoggedIn = true;
    } catch (err) {
      // Token is invalid or expired
      res.clearCookie("token");
    }
  }
  res.render("Home", { isLoggedIn });
});
app.get("/Dashboard", isloggedin, (req, res) => {
  Hisab.find({ owner: req.user.newuser })
    .then((hisabs) => {
      res.render("index", { hisabs });
    })
    .catch((err) => {
      console.error(err);
      res.render("index", { hisabs: [] });
    });
});
app.get("/register", (req, res) => {
  res.render("register");
});
app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/createHisab", isloggedin, (req, res) => {
  res.render("createHisab");
});

// all the post routes

app.post("/registeruser", async (req, res) => {
  console.log(req.body);
  const { username, fullname, password, email } = req.body;
  const existinguser = await user.findOne({ email });
  if (existinguser) {
    return res.status(400).send("user already exists");
  }
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);
  //   creating the new user

  const newuser = new user({
    username,
    fullname,
    email,
    password: hash,
  });
  await newuser.save();
  const token = jwt.sign(
    { email: email, newuser: newuser._id }, 
    process.env.JWT_SECRET || "secretkey", 
    { expiresIn: "10h" }
  );
  res.cookie("token", token);
  res.redirect("/dashboard");
});
app.post("/loginuser", async (req, res) => {
  const { email, password } = req.body;
  const existingUser = await user.findOne({ email });
  if (!existingUser) {
    return res.status(400).send("user not found");
  }
  const isvalid = await bcrypt.compare(password, existingUser.password);
  if (!isvalid) {
    return res.status(400).send("invalid password");
  }
  const token = jwt.sign(
    { email: email, newuser: existingUser._id },
    process.env.JWT_SECRET || "secretkey",
    { expiresIn: "10h" }
  );
  res.cookie("token", token);
  res.redirect("/dashboard");
});
app.post("/createNewHisab", isloggedin, async (req, res) => {
  try {
    const {
      hisabname,
      hisabdescription,
      isencrypted,
      passcode,
      confirmPasscode,
      isshareable,
    } = req.body;

    if (isencrypted) {
      if (!passcode || !confirmPasscode) {
        return res.status(400).send("Passcode is required for encrypted hisab");
      }
      if (passcode !== confirmPasscode) {
        return res.status(400).send("Passcodes do not match");
      }
      if (passcode.length < 4 || passcode.length > 6) {
        return res.status(400).send("Passcode must be between 4 and 6 digits");
      }
    }

    const newHisab = new Hisab({
      name: hisabname,
      description: hisabdescription,
      isEncrypted: isencrypted === "on",
      passcode: isencrypted === "on" ? passcode : undefined,
      isShareable: isshareable === "on",
      owner: req.user.newuser,
    });
    console.log(newHisab);

    await newHisab.save();
    res.redirect("/Dashboard");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error creating hisab");
  }
});

// all the middleware

app.get("/viewHisab", isloggedin, (req, res) => {
  res.render("viewhisab");
});
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

app.get("/viewHisab/:id", isloggedin, async (req, res) => {
  try {
    const hisab = await Hisab.findById(req.params.id);
    if (!hisab) {
      return res.status(404).send("Hisab not found");
    }

    // Check if the hisab is encrypted
    if (hisab.isEncrypted) {
      // Check if the hisab is already verified in the session
      if (
        !req.session.verifiedHisab ||
        req.session.verifiedHisab !== hisab._id.toString()
      ) {
        return res.render("verifyPasscode", {
          hisabId: hisab._id,
          error: null,
        });
      }
    }

    // If not encrypted or already verified, render the viewHisab page
    res.render("viewhisab", { hisab });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error accessing hisab");
  }
});

app.post("/verifyHisabPasscode", isloggedin, async (req, res) => {
  try {
    const { hisabId, passcode } = req.body;
    const hisab = await Hisab.findById(hisabId);

    if (!hisab) {
      return res.status(404).send("Hisab not found");
    }

    const isValid = await hisab.verifyPasscode(passcode);
    if (!isValid) {
      return res.render("verifyPasscode", {
        hisabId,
        error: "Invalid passcode. Please try again.",
      });
    }

    // Store verified hisab ID in session
    req.session.verifiedHisab = hisabId;
    res.redirect(`/viewHisab/${hisabId}`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error verifying passcode");
  }
});

// Add transaction routes
app.get("/addTransaction/:id", isloggedin, async (req, res) => {
  try {
    const hisab = await Hisab.findById(req.params.id);
    if (!hisab) {
      return res.status(404).send("Hisab not found");
    }
    res.render("addTransaction", { hisab });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error accessing hisab");
  }
});

app.post("/addTransaction/:id", isloggedin, async (req, res) => {
  try {
    const { description, amount, type } = req.body;
    const hisab = await Hisab.findById(req.params.id);

    if (!hisab) {
      return res.status(404).send("Hisab not found");
    }

    hisab.transactions.push({
      description,
      amount: parseFloat(amount),
      type,
    });

    await hisab.save();
    res.redirect(`/viewHisab/${req.params.id}`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error adding transaction");
  }
});

// Edit hisab routes
app.get("/editHisab/:id", isloggedin, async (req, res) => {
  try {
    const hisab = await Hisab.findById(req.params.id);
    if (!hisab) {
      return res.status(404).send("Hisab not found");
    }
    res.render("editHisab", { hisab });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error accessing hisab");
  }
});

app.post("/editHisab/:id", isloggedin, async (req, res) => {
  try {
    const { name, description, isEncrypted, passcode, isShareable } = req.body;
    const hisab = await Hisab.findById(req.params.id);

    if (!hisab) {
      return res.status(404).send("Hisab not found");
    }

    hisab.name = name;
    hisab.description = description;
    hisab.isEncrypted = isEncrypted === "on";
    hisab.isShareable = isShareable === "on";

    if (isEncrypted === "on" && passcode) {
      hisab.passcode = passcode;
    }

    await hisab.save();
    res.redirect(`/viewHisab/${req.params.id}`);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error updating hisab");
  }
});

// Delete hisab route
app.post("/deleteHisab/:id", isloggedin, async (req, res) => {
  try {
    const hisab = await Hisab.findById(req.params.id);

    if (!hisab) {
      return res.status(404).send("Hisab not found");
    }

    await Hisab.findByIdAndDelete(req.params.id);
    res.redirect("/Dashboard");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error deleting hisab");
  }
});

// Delete transaction route
app.post('/deleteTransaction/:hisabId/:transactionId', isloggedin, async (req, res) => {
    try {
        const hisab = await Hisab.findById(req.params.hisabId);
        
        if (!hisab) {
            return res.status(404).send("Hisab not found");
        }

        hisab.transactions = hisab.transactions.filter(
            transaction => transaction._id.toString() !== req.params.transactionId
        );

        await hisab.save();
        res.redirect(`/viewHisab/${req.params.hisabId}`);
    } catch (error) {
        console.error(error);
        res.status(500).send("Error deleting transaction");
    }
});

// Shared hisab routes
app.get('/shared/:token', async (req, res) => {
    try {
        const hisab = await Hisab.findOne({ shareToken: req.params.token });
        
        if (!hisab) {
            return res.status(404).send("Shared hisab not found");
        }

        if (!hisab.isShareable) {
            return res.status(403).send("This hisab is not shareable");
        }

        // Check if the hisab is encrypted
        if (hisab.isEncrypted) {
            // Check if the hisab is already verified in the session
            if (!req.session.verifiedSharedHisab || req.session.verifiedSharedHisab !== hisab._id.toString()) {
                return res.render('verifyPasscode', { 
                    hisabId: hisab._id,
                    error: null,
                    isShared: true
                });
            }
        }

        // Check if user is logged in
        const isLoggedIn = req.cookies.token ? true : false;

        res.render('sharedHisab', { 
            hisab,
            isLoggedIn
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error accessing shared hisab");
    }
});

app.post('/verifySharedHisabPasscode', async (req, res) => {
    try {
        const { hisabId, passcode } = req.body;
        const hisab = await Hisab.findById(hisabId);
        
        if (!hisab) {
            return res.status(404).send("Hisab not found");
        }

        const isValid = await hisab.verifyPasscode(passcode);
        if (!isValid) {
            return res.render('verifyPasscode', {
                hisabId,
                error: "Invalid passcode. Please try again.",
                isShared: true
            });
        }

        // Store verified hisab ID in session
        req.session.verifiedSharedHisab = hisabId;
        res.redirect(`/shared/${hisab.shareToken}`);
    } catch (error) {
        console.error(error);
        res.status(500).send("Error verifying passcode");
    }
});

// Profile routes
app.get("/profile", isloggedin, async (req, res) => {
  try {
    const userData = await user.findById(req.user.newuser);
    if (!userData) {
      return res.status(404).send("User not found");
    }

    const hisabs = await Hisab.find({ owner: req.user.newuser });
    
    res.render("Profile", { 
      user: userData, 
      hisabs: hisabs
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error accessing profile");
  }
});

app.post("/updateProfile", isloggedin, async (req, res) => {
  try {
    const { username, fullname, email } = req.body;
    const userId = req.user.newuser;
    
    // Check if username or email is already taken by another user
    const existingUser = await user.findOne({
      $or: [
        { username: username },
        { email: email }
      ],
      _id: { $ne: userId }
    });
    
    if (existingUser) {
      const userData = await user.findById(userId);
      const hisabs = await Hisab.find({ owner: userId });
      
      return res.render("Profile", {
        user: userData,
        hisabs: hisabs,
        error: "Username or email is already taken by another user."
      });
    }
    
    // Update user profile
    const updatedUser = await user.findByIdAndUpdate(
      userId,
      { username, fullname, email },
      { new: true }
    );
    
    if (!updatedUser) {
      return res.status(404).send("User not found");
    }
    
    // Update JWT token with new email if it changed
    if (email !== req.user.email) {
      const token = jwt.sign(
        { email: email, newuser: userId },
        process.env.JWT_SECRET || "secretkey",
        { expiresIn: "10h" }
      );
      res.cookie("token", token);
    }
    
    const hisabs = await Hisab.find({ owner: userId });
    
    res.render("Profile", {
      user: updatedUser,
      hisabs: hisabs,
      success: "Profile updated successfully"
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error updating profile");
  }
});

app.post("/changePassword", isloggedin, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const userId = req.user.newuser;
    
    // Get user data
    const userData = await user.findById(userId);
    if (!userData) {
      return res.status(404).send("User not found");
    }
    
    // Verify current password
    const isValid = await bcrypt.compare(currentPassword, userData.password);
    if (!isValid) {
      const hisabs = await Hisab.find({ owner: userId });
      
      return res.render("Profile", {
        user: userData,
        hisabs: hisabs,
        error: "Current password is incorrect"
      });
    }
    
    // Check if new password and confirm password match
    if (newPassword !== confirmPassword) {
      const hisabs = await Hisab.find({ owner: userId });
      
      return res.render("Profile", {
        user: userData,
        hisabs: hisabs,
        error: "New password and confirm password do not match"
      });
    }
    
    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);
    
    // Update password
    const updatedUser = await user.findByIdAndUpdate(
      userId,
      { password: hashedPassword },
      { new: true }
    );
    
    const hisabs = await Hisab.find({ owner: userId });
    
    res.render("Profile", {
      user: updatedUser,
      hisabs: hisabs,
      success: "Password changed successfully"
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error changing password");
  }
});

// Update the listener to be compatible with both local development and Vercel
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`App is running on port ${PORT}`);
  });
}

module.exports = app;
