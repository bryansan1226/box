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

//Function to verify user authentication token
const verifyToken = async (req, res, next) => {
  try {
    /*Makes attempt to extract token from 'Authorization' header sent from 
    the client*/
    const token = req.header("Authorization").replace("Bearer ", "");
    //Handles error message if no token is provided
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }
    //Verifies the token using JWT and the secret key and assigns this information to req.user
    const decoded = await promisify(jwt.verify)(token, SECRET_KEY);
    req.user = decoded;
    //To be removed, for testing purposes
    //console.log("In verify token req.user is showing as:", req.user);
    next();
  } catch (error) {
    console.error(error);
    return res.status(401).json({ message: "Invalid token" });
  }
};
/*getAllUsers and findByUsername are functions to test the information
  in the database and ensure that the correct information is being stored by querying 
  the database.
  findByUsername is used to locate a particular user and retrieve their information once authenticated */
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
//Function for creating a new user in the database
const createAccount = async (req, res) => {
  //Gets the user information from the request body
  const { firstName, lastName, username, password, email, timestamp } =
    req.body;
  const salt = await bcrypt.genSalt(saltRounds);
  //Hashes the user's password using bcrypt and the generated salt
  const hashedPassword = await bcrypt.hash(password, salt);
  //Prepares an SQL query for the user's data
  const query =
    "INSERT INTO users (first_name, last_name, username, password, email, created_on) VALUES ($1,$2,$3,$4,$5,$6)";
  //Executes the SQL query using the connection pool
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
      //If creation is successful, generates a JWT
      //JWT is used to sign the user in after the account is created
      const token = jwt.sign({ username }, SECRET_KEY);
      res.status(200).json({ token, message: "Account successfully created." });
    })
    .catch((error) => {
      console.error("Error inserting data:", error);
      res.status(500).json({ error: "An error occured while inserting data." });
    });
};

//This function is used to authenticate a user and returns a token if authenticated.
const login = async (req, res) => {
  //Retrieves username and password from the request body
  const { username, password } = req.body;
  //Queries the database using the username to locate the user
  try {
    const query = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);
    //Sets the user using the query result, should be the first and only result assuming no duplicate usernames
    const user = query.rows[0];
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    //Uses bcrypt to compare the password with the hashed password stored in the database
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
      //If the passwords match, a JWT is generated with the user's username
      const token = jwt.sign({ username }, SECRET_KEY);
      res.json({ token });
    });
  } catch (error) {
    console.error("Error during login", error);
    res.status(500).json({ error: "Internal error" });
  }
};
//Retrieves user information based on the user's username
const getUser = async (req, res) => {
  try {
    //For testing purposes
    console.log(
      "When calling findbyusername, you're passing:",
      req.user.username
    );
    //Retrieves username from the request and then calls a function to query the database.
    const username = req.user.username;
    //If the username is found, retrieves user information and attaches it to 'user'
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

const getUserPosts = async (req, res) => {
  try {
    const query = "SELECT * FROM posts WHERE user_id = $1";
    const user_id = req.params.user_id;
    const result = await pool.query(query, [user_id]);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error finding posts by user_id", error);
    throw error;
  }
};
const getMessages = async (req, res) => {
  try {
    const query = `SELECT messages.*, users.first_name, users.last_name
    FROM messages
    LEFT JOIN users ON messages.sender_id = users.user_id
    WHERE messages.receiver_id = $1 OR messages.sender_id=$1;`;
    const user_id = req.params.user_id;
    const result = await pool.query(query, [user_id]);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error finding messages for user_id", error);
    throw error;
  }
};
const getConversation = async (req, res) => {
  try {
    const { user_id, conversation_id } = req.query;
    //console.log(user_id, conversation_id);
    const query = `SELECT messages.*, users.first_name, users.last_name
    FROM messages
    LEFT JOIN users ON messages.sender_id = users.user_id
    WHERE (messages.receiver_id = $1 AND messages.sender_id =$2) OR (messages.receiver_id=$2 AND messages.sender_id=$1);`;
    const result = await pool.query(query, [user_id, conversation_id]);
    //console.log(result);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error finding conversation", error);
    throw error;
  }
};
const getComments = async (req, res) => {
  try {
    const query = "SELECT * FROM comments WHERE post_id = $1";
    const post_id = req.params.post_id;
    const result = await pool.query(query, [post_id]);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error finding posts by user_id", error);
    throw error;
  }
};
const getLikes = async (req, res) => {
  try {
    const query = "SELECT * FROM likes WHERE post_id = $1";
    const post_id = req.params.post_id;
    const result = await pool.query(query, [post_id]);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error finding posts by user_id", error);
    throw error;
  }
};
const getFollowingPosts = async (req, res) => {
  try {
    const query = `SELECT *
    FROM posts
    RIGHT JOIN followers ON posts.user_id = followers.user_id
    WHERE followers.follower_user_id = $1`;
    const user_id = req.params.user_id;
    const result = await pool.query(query, [user_id]);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error finding posts by user_id", error);
    throw error;
  }
};

const newPost = async (req, res) => {
  const { user_id, content, media, created_at } = req.body;
  const query =
    "INSERT INTO posts (user_id, content, media, created_at) VALUES ($1,$2,$3,$4)";
  pool
    .query(query, [user_id, content, media, created_at])
    .then(() => {
      res.status(200).json({ message: "Post successfully created." });
    })
    .catch((error) => {
      console.error("Error inserting data:", error);
      res.status(500).json({ error: "An error occured while inserting data." });
    });
};

const newMessage = async (req, res) => {
  const { sender_id, receiver_id, content, created_at } = req.body;
  const query =
    "INSERT INTO messages (sender_id, receiver_id, content, created_at,is_read) VALUES ($1,$2,$3,$4,$5)";
  pool
    .query(query, [sender_id, receiver_id, content, created_at, false])
    .then(() => {
      res.status(200).json({ message: "Message sent" });
    })
    .catch((error) => {
      console.error("Error sending message:", error);
      res
        .status(500)
        .json({ error: "An error occured while sending message." });
    });
};

const newComment = async (req, res) => {
  const { post_id, user_id, content, created_at } = req.body;
  const query =
    "INSERT INTO comments (post_id, user_id, content, created_at) VALUES ($1,$2,$3,$4)";
  pool
    .query(query, [post_id, user_id, content, created_at])
    .then(() => {
      res.status(200).json({ message: "Comment successfully created." });
    })
    .catch((error) => {
      console.error("Error inserting data:", error);
      res.status(500).json({ error: "An error occured while inserting data." });
    });
};

const searchUser = async (req, res) => {
  try {
    const query = `SELECT * FROM users
    WHERE username ILIKE $1
    OR first_name ILIKE $1
    OR last_name ILIKE $1
    OR (first_name || ' ' || last_name) ILIKE $1`;
    const searchQuery = req.params.searchQuery;
    const result = await pool.query(query, [searchQuery]);
    res.status(200).json(result);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
};
const newFollow = async (req, res) => {
  const { user_id, follower_id, created_at } = req.body;
  const query =
    "INSERT INTO followers (user_id, follower_user_id, created_at) VALUES ($1,$2,$3)";
  pool
    .query(query, [user_id, follower_id, created_at])
    .then(() => {
      res.status(200).json({ message: "Follow successful." });
    })
    .catch((error) => {
      console.error("Error inserting data:", error);
      res.status(500).json({ error: "An error occured while inserting data." });
    });
};
const likePost = async (req, res) => {
  const { post_id, user_id, created_at } = req.body;
  const query =
    "INSERT INTO likes (post_id, user_id, created_at) VALUES ($1,$2,$3)";
  pool
    .query(query, [post_id, user_id, created_at])
    .then(() => {
      res.status(200).json({ message: "Like successful." });
    })
    .catch((error) => {
      console.error("Error inserting data:", error);
      res.status(500).json({ error: "An error occured while inserting data." });
    });
};
const dislikePost = async (req, res) => {
  const { user_id, post_id } = req.body;
  const query = "DELETE FROM likes WHERE user_id = $1 AND post_id=$2";
  pool
    .query(query, [user_id, post_id])
    .then(() => {
      res.status(200).json({
        message: "dislike successful.",
      });
    })
    .catch((error) => {
      console.error("Error deleting data: ", error);
      res.status(500).json({ error: "An error occured while deleting data." });
    });
};
const unfollow = async (req, res) => {
  const { user_id, follower_id } = req.body;
  const query =
    "DELETE FROM followers WHERE user_id = $1 AND follower_user_id=$2";
  pool
    .query(query, [user_id, follower_id])
    .then(() => {
      res.status(200).json({
        message: "Unfollow successful.",
      });
    })
    .catch((error) => {
      console.error("Error deleting data: ", error);
      res.status(500).json({ error: "An error occured while deleting data." });
    });
};
const findByUserID = async (req, res) => {
  try {
    const query = "SELECT * FROM users WHERE user_id = $1";
    const user_id = req.params.user_id;
    // console.log("User ID is:" + user_id);
    const result = await pool.query(query, [user_id]);
    // console.log(result.rows);
    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error("Error finding posts by user_id", error);
    throw error;
  }
};

const following = async (req, res) => {
  try {
    const query =
      "SELECT * FROM followers WHERE user_id = $1 AND follower_user_id=$2";
    const user_id = req.params.user_id;
    const follower_id = req.params.follower_id;
    const result = await pool.query(query, [user_id, follower_id]);
    // console.log(result.rows);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error finding follow relationship", error);
    throw error;
  }
};
const getFollowing = async (req, res) => {
  try {
    //const query = "SELECT * FROM followers WHERE follower_user_id=$1";
    const query = `SELECT followers.*, users.first_name, users.last_name
    FROM followers
    LEFT JOIN users ON followers.user_id = users.user_id
    WHERE followers.follower_user_id = $1;`;
    const follower_id = req.params.follower_id;
    const result = await pool.query(query, [follower_id]);
    // console.log(result.rows);
    res.status(200).json(result);
  } catch (error) {
    console.error("Error finding follow relationship", error);
    throw error;
  }
};

app.get("/", (req, res) => {
  res.send("Hello World!");
});
app.get("/users", getAllUsers);
app.post("/api/createAccount", createAccount);
//If verifyToken encounters an error(e.g. it is unable to verify the user information) getUser will not run
app.get("/api/user", verifyToken, getUser);
app.post("/api/login", login);
app.post("/api/newPost", newPost);
app.post("/api/newComment", newComment);
app.get("/api/getUserPosts/:user_id", getUserPosts);
app.get("/api/getMessages/:user_id", getMessages);
app.get("/api/getConversation", getConversation);
app.get("/api/getComments/:post_id", getComments);
app.get("/api/getLikes/:post_id", getLikes);
app.post("/api/likePost", likePost);
app.delete("/api/dislikePost", dislikePost);
app.get("/api/findByUserID/:user_id", findByUserID);
app.get("/api/getFollowingPosts/:user_id", getFollowingPosts);
app.get("/api/search/users/:searchQuery", searchUser);
app.post("/api/newFollow", newFollow);
app.delete("/api/unfollow", unfollow);
app.get("/api/following/:user_id/:follower_id", following);
app.get("/api/getFollowing/:follower_id", getFollowing);
app.post("/api/newMessage", newMessage);

app.listen(PORT, () => {
  console.log(`Server listening on the port  ${PORT}`);
});
