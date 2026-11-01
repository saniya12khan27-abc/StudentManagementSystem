
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");
const bcrypt = require("bcryptjs");
const path = require("path");
require("dotenv").config();

const Student = require("./models/student");
const Admin = require("./models/admin");

const app = express();
const PORT = process.env.PORT || 5000;

// Check required environment settings.
if (
  !process.env.MONGODB_URI ||
  !process.env.ADMIN_USERNAME ||
  !process.env.ADMIN_PASSWORD ||
  !process.env.SESSION_SECRET
) {
  throw new Error(
    "Please configure MONGODB_URI, ADMIN_USERNAME, ADMIN_PASSWORD and SESSION_SECRET in .env"
  );
}

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: "20kb" }));

// Store login sessions in MongoDB.
app.use(session({
  name: "student_admin_session",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: "admin_sessions"
  }),
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 60 * 60 * 1000
  }
}));

// Serve public files, but do not expose the dashboard directly.
app.use(express.static(path.join(__dirname, "public"), {
  index: false
}));

app.get("/index.html", (req, res) => {
  res.redirect("/");
});

// Protect the dashboard and student APIs.
function requireAdmin(req, res, next) {
  if (!req.session || !req.session.adminId) {
    if (req.path.startsWith("/api/")) {
      return res.status(401).json({
        message: "Please log in as admin."
      });
    }

    return res.redirect("/login.html");
  }

  next();
}

// Login page.
app.get("/login.html", (req, res) => {
  if (req.session.adminId) {
    return res.redirect("/");
  }

  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Protected student dashboard.
app.get("/", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Check login status.
app.get("/api/auth/me", (req, res) => {
  if (!req.session.adminId) {
    return res.status(401).json({
      authenticated: false
    });
  }

  res.json({
    authenticated: true,
    username: req.session.adminUsername
  });
});

// Admin login.
app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      !username.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Please enter username and password."
      });
    }

    const admin = await Admin.findOne({
      username: username.trim()
    });

    if (
      !admin ||
      !(await bcrypt.compare(password, admin.passwordHash))
    ) {
      return res.status(401).json({
        message: "Invalid username or password."
      });
    }

    // Create a fresh session after successful login.
    req.session.regenerate((error) => {
      if (error) {
        return next(error);
      }

      req.session.adminId = admin._id.toString();
      req.session.adminUsername = admin.username;

      req.session.save((saveError) => {
        if (saveError) {
          return next(saveError);
        }

        res.json({
          message: "Login successful.",
          username: admin.username
        });
      });
    });
  } catch (error) {
    next(error);
  }
});

// Admin logout.
app.post("/api/auth/logout", requireAdmin, (req, res, next) => {
  req.session.destroy((error) => {
    if (error) {
      return next(error);
    }

    res.clearCookie("student_admin_session", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    });

    res.json({
      message: "Logged out successfully."
    });
  });
});

// All student APIs require admin login.
app.use("/api/students", requireAdmin);

// Get and search students.
app.get("/api/students", async (req, res, next) => {
  try {
    const search = String(req.query.search || "").slice(0, 100);

    const students = await Student.find({
      $or: [
        { name: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } }
      ]
    }).sort({ createdAt: -1 });

    res.json(students);
  } catch (error) {
    next(error);
  }
});

// Add a student.
app.post("/api/students", async (req, res, next) => {
  try {
    const { name, email, course, year } = req.body || {};

    if (
      typeof name !== "string" || !name.trim() ||
      typeof email !== "string" || !email.trim() ||
      typeof course !== "string" || !course.trim() ||
      typeof year !== "string" || !year.trim()
    ) {
      return res.status(400).json({
        message: "Please fill all student fields."
      });
    }

    const student = await Student.create({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      course: course.trim(),
      year: year.trim()
    });

    res.status(201).json(student);
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "This email is already registered."
      });
    }

    next(error);
  }
});

// Update a student.
app.put("/api/students/:id", async (req, res, next) => {
  try {
    const { name, email, course, year } = req.body || {};

    if (
      typeof name !== "string" || !name.trim() ||
      typeof email !== "string" || !email.trim() ||
      typeof course !== "string" || !course.trim() ||
      typeof year !== "string" || !year.trim()
    ) {
      return res.status(400).json({
        message: "Please fill all student fields."
      });
    }

    const student = await Student.findByIdAndUpdate(
      req.params.id,
      {
        name: name.trim(),
        email: email.trim().toLowerCase(),
        course: course.trim(),
        year: year.trim()
      },
      {
        new: true,
        runValidators: true
      }
    );

    if (!student) {
      return res.status(404).json({
        message: "Student not found."
      });
    }

    res.json(student);
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        message: "This email is already registered."
      });
    }

    if (error.name === "CastError") {
      return res.status(400).json({
        message: "Invalid student ID."
      });
    }

    next(error);
  }
});

// Delete a student.
app.delete("/api/students/:id", async (req, res, next) => {
  try {
    const student = await Student.findByIdAndDelete(req.params.id);

    if (!student) {
      return res.status(404).json({
        message: "Student not found."
      });
    }

    res.json({
      message: "Student deleted successfully."
    });
  } catch (error) {
    if (error.name === "CastError") {
      return res.status(400).json({
        message: "Invalid student ID."
      });
    }

    next(error);
  }
});

// Create the first admin account if it does not exist.
async function initializeAdmin() {
  const username = process.env.ADMIN_USERNAME.trim();
  const password = process.env.ADMIN_PASSWORD;

  const existingAdmin = await Admin.findOne({ username });

  if (existingAdmin) {
    console.log("Admin account already exists.");
    return;
  }

  const passwordHash = await bcrypt.hash(password, 12);

  await Admin.create({
    username,
    passwordHash
  });

  console.log("Initial admin account created.");
}

// Handle server errors.
app.use((error, req, res, next) => {
  console.error("Request error:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    message: "An unexpected server error occurred."
  });
});

// Connect to MongoDB and start the server.
async function startServer() {
  try {
    const mongoURI = process.env.MONGODB_URI;

    if (!mongoURI) {
      throw new Error("MongoDB URI is missing. Please check your .env file.");
    }

    if (!mongoURI.startsWith("mongodb://") &&
        !mongoURI.startsWith("mongodb+srv://")) {
      throw new Error("Invalid MongoDB URI format.");
    }

    console.log("Connecting to MongoDB...");

    await mongoose.connect(mongoURI, {
      serverSelectionTimeoutMS: 10000
    });

    console.log("MongoDB connected successfully!");

    await initializeAdmin();

    app.listen(PORT, () => {
      console.log(`Server is running on port ${PORT}`);
    });

  } catch (error) {
    console.error("MongoDB / Server startup error:");

    if (error.message.includes("authentication failed")) {
      console.error("Check your MongoDB username and password.");
    } else if (
      error.message.includes("ENOTFOUND") ||
      error.message.includes("querySrv")
    ) {
      console.error("Check your MongoDB cluster hostname and URI.");
    } else if (
      error.message.includes("IP") ||
      error.message.includes("ECONNREFUSED")
    ) {
      console.error("Check MongoDB Atlas Network Access and IP settings.");
    } else {
      console.error(error.message);
    }

    process.exit(1);
  }
}

startServer();