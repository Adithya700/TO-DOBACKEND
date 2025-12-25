const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 8080;
const MONGOURL = process.env.MONGOURL;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: "*",
  })
);

// MongoDB Connection
mongoose
  .connect(MONGOURL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

// Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});

const taskSchema = new mongoose.Schema({
  text: String,
  status: String,
  priority: String,
  userId: mongoose.Schema.Types.ObjectId,
});

// Models
const User = mongoose.model("User", userSchema);
const Task = mongoose.model("Task", taskSchema);

// 🔐 Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

// 🧾 Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });
  await user.save();

  res.json({ message: "User registered successfully" });
});

// 🔑 Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ token });
});

// 📥 Get Tasks
app.get("/tasks", authMiddleware, async (req, res) => {
  const tasks = await Task.find({ userId: req.userId });
  res.json(tasks);
});

// ➕ Add Task
app.post("/tasks", authMiddleware, async (req, res) => {
  const { text, status, priority } = req.body;

  if (!text) {
    return res.status(400).json({ message: "Task text is required" });
  }

  const task = new Task({
    text,
    status: status || "pending",
    priority: priority || "medium",
    userId: req.userId,
  });

  await task.save();
  res.json(task);
});

// ❌ Delete Task
app.delete("/tasks/:id", authMiddleware, async (req, res) => {
  const task = await Task.findOneAndDelete({
    _id: req.params.id,
    userId: req.userId,
  });

  if (!task) {
    return res.status(404).json({ message: "Task not found" });
  }

  res.json({ message: "Task deleted successfully" });
});

// 🔄 Update Status
app.patch("/tasks/:id/status", authMiddleware, async (req, res) => {
  const { status } = req.body;

  const task = await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.userId },
    { status },
    { new: true }
  );

  if (!task) return res.status(404).json({ message: "Task not found" });

  res.json(task);
});

// ⭐ Update Priority
app.patch("/tasks/:id/priority", authMiddleware, async (req, res) => {
  const { priority } = req.body;

  const task = await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.userId },
    { priority },
    { new: true }
  );

  if (!task) return res.status(404).json({ message: "Task not found" });

  res.json(task);
});

// 🚀 Start Server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
