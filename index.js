require("dotenv").config({ path: __dirname + "/.env" });
const express = require("express");
const pool = require(__dirname + "/db.config.js");
const cors = require("cors");
const app = express();

const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());

const getUsers = (req, res) => {
  pool.query("SELECT * FROM users", (error, users) => {
    if (error) {
      throw error;
    }
    res.status(200).json(users.rows);
  });
};

const createAccount = (req, res) => {
  const { firstName, lastName, username, password, email, timestamp } =
    req.body;
  const query =
    "INSERT INTO users (first_name, last_name, username, password, email, created_on) VALUES ($1,$2,$3,$4,$5,$6)";

  pool
    .query(query, [firstName, lastName, username, password, email, timestamp])
    .then(() => {
      res.status(200).json({ message: "Account successfully created." });
    })
    .catch((error) => {
      console.error("Error inserting data:", error);
      res.status(500).json({ error: "An error occured while inserting data." });
    });
};

app.get("/", (req, res) => {
  res.send("Hello World!");
});
app.get("/users", getUsers);
app.post("/api/createAccount", createAccount);

app.listen(PORT, () => {
  console.log(`Server listening on the port  ${PORT}`);
});
