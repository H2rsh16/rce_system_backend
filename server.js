const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcryptjs = require("bcryptjs");
require("dotenv").config();

const app = express();
app.set("trust proxy", 1);

// CORS configuration
const corsOptions = {
  origin: "https://rce-system-backend.onrender.com",
  credentials: true,
};
app.use(cookieParser());
app.use(cors(corsOptions));
app.use(express.json());
app.use(bodyParser.json());

// MongoDB connection
mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB database.");
  })
  .catch((err) => {
    console.error("Database connection failed:", err.stack);
  });

// User schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Register route
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const hashedPassword = await bcryptjs.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res
      .status(400)
      .json({ message: "User registration failed", error: error.message });
  }
});

// Login route
app.post("/login", async (req, res) => {
  let { email, password } = req.body;
  email = email.trim().toLowerCase(); // normalize email

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const isValidPassword = await bcryptjs.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user._id, name: user.name, email: user.email },
      process.env.JWT_KEY,
      { algorithm: "HS256", expiresIn: "1h" },
    );
    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 3600000,
      secure: true,
      sameSite: "None",
    });

    res.json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Internal server error", error });
  }
});

app.get("/profile", (req, res) => {
  const token = req.cookies["token"];

  if (!token) {
    return res.status(401).json({ message: "Un-Authorized Access" });
  }

  jwt.verify(token, process.env.JWT_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Failed to authenticate token" });
    }

    res.json({
      message: "Successfully Authenticated",
      data: {
        id: decoded.id,
        name: decoded.name,
        email: decoded.email,
      },
    });
  });
});

app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "None",
  });
  return res.json({ message: "Log-out Successfully" });
});

app.get("/health", (req, res) => {
  return res.json({ message: "System Working well!!" });
});

// Start the server
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
