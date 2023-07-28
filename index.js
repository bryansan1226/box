require("dotenv").config({ path: __dirname + "/.env" });
const express = require("express");
const pool = require(__dirname + "/db.config.js");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const saltRounds = 10;

const app = express();

const SECRET_KEY = "secretkey";

const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());

const verifyToken = async (req, res, next) => {
  try {
    const token = req.header("Authorization").replace("Bearer ", "");
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }
    const decoded = await promisify(jwt.verify)(token, SECRET_KEY);
    req.user = decoded;
    console.log("In verify token req.user is showing as:", req.user);
    next();
  } catch (error) {
    console.error(error);
    return res.status(401).json({ message: "Invalid token" });
  }
};

const getAllUsers = (req, res) => {
  pool.query("SELECT * FROM users", (error, users) => {
    if (error) {
      throw error;
    }
    res.status(200).json(users.rows);
  });
};
const findUserByUsername = async (username) => {
  try {
    const query = "SELECT * FROM users WHERE username = $1";
    const values = [username];
    const { rows } = await pool.query(query, values);
    return rows[0]; // Return the first user found (assuming username is unique)
  } catch (error) {
    console.error("Error finding user by username", error);
    throw error;
  }
};
const createAccount = async (req, res) => {
  const { firstName, lastName, username, password, email, timestamp } =
    req.body;
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(password, salt);
  const query =
    "INSERT INTO users (first_name, last_name, username, password, email, created_on) VALUES ($1,$2,$3,$4,$5,$6)";

  pool
    .query(query, [
      firstName,
      lastName,
      username,
      hashedPassword,
      email,
      timestamp,
    ])
    .then(() => {
      const token = jwt.sign({ username }, SECRET_KEY);
      res.status(200).json({ token, message: "Account successfully created." });
    })
    .catch((error) => {
      console.error("Error inserting data:", error);
      res.status(500).json({ error: "An error occured while inserting data." });
    });
};
const login = async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    const user = query.rows[0];
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
      const token = jwt.sign({ username }, SECRET_KEY);
      res.json({ token });
    });
  } catch (error) {
    console.error("Error during login", error);
    res.status(500).json({ error: "Internal error" });
  }
};
const getUser = async (req, res) => {
  try {
    console.log(
      "When calling findbyusername, you're passing:",
      req.user.username
    );
    const username = req.user.username;
    const user = await findUserByUsername(username);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.status(200).json(user);
  } catch (error) {
    console.error("Error fetching user information", error);
    res
      .status(500)
      .json({ error: "An error occurred while fetching user information" });
  }
};

app.get("/", (req, res) => {
  res.send("Hello World!");
});
app.get("/users", getAllUsers);
app.post("/api/createAccount", createAccount);
app.get("/api/user", verifyToken, getUser);
app.post("/api/login", login);
app.listen(PORT, () => {
  console.log(`Server listening on the port  ${PORT}`);
});
