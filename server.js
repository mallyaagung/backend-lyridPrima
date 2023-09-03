const express = require("express");
const mysql = require("mysql");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, "uploads/");
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
      const fileExtentions = path.extname(file.originalname);
      cb(null, file.fieldname + "-" + uniqueSuffix + fileExtentions);
    },
  }),
  fileFilter: (req, file, cb) => {
    if (file.fieldname === "photo") {
      // filter mimetype
      if (file.mimetype === "image/jpg" || file.mimetype === "image/jpeg") {
        cb(null, true);
      } else {
        cb({ message: "Photo extension only can .jpg and .jpeg" }, false);
      }
    }
  },
  limits: { fileSize: 300 * 1024 },
});

const app = express();
const port = 8000;

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "staff_management",
});

const corsOptions = {
  origin: "http://localhost:3000",
};
app.use(cors(corsOptions));
app.use(express.json());
app.use("/img", express.static("./uploads"));
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(bodyParser.json());

db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL: " + err.stack);
    return;
  }
  console.log("Connected to MySQL as id " + db.threadId);
});

//LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const query = "SELECT * FROM users WHERE email = ?";

  db.query(query, [email], (err, results) => {
    if (err) {
      console.error("Error executing MySQL query: " + err.message);
      return res.status(500).json({ error: "Database error" });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = results[0];
    console.log(user);

    // Compare the provided password with the hashed password stored in the database
    bcrypt.compare(password, user.password, (bcryptErr, isMatch) => {
      if (bcryptErr) {
        console.error("Error comparing passwords: " + bcryptErr.message);
        return res.status(500).json({ error: "Authentication error" });
      }

      if (isMatch) {
        // Passwords match, so it's a successful login
        return res.json(user);
      } else {
        // Passwords don't match, so it's invalid credentials
        return res.status(401).json({ error: "Invalid credentials" });
      }
    });
  });
});

// GET
app.get("/users", (req, res) => {
  db.query("SELECT * FROM users", (err, results) => {
    if (err) {
      console.error("Error querying MySQL: " + err.stack);
      return res.status(500).json({ error: "Database error" });
    }
    if (results.length === 0) {
      return res.json({ message: "No users found" });
    }
    return res.json(results);
  });
});

// CREATE
app.post("/users", upload.single("photo"), async (req, res) => {
  const { name, email, password, role } = req.body;
  db.query(
    "SELECT COUNT(*) AS count FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        console.error("Error executing MySQL query: " + err.stack);
        return res.status(500).json({ error: "Database error" });
      }

      if (results[0].count > 0) {
        return res.status(400).json({ error: "Email already exists" });
      }

      try {
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const id = uuidv4();

        const newUsers = {
          id,
          name,
          email,
          password: hashedPassword,
          role,
        };

        db.query("INSERT INTO users SET ?", newUsers, (err, result) => {
          if (err) {
            console.error("Error inserting into MySQL: " + err.stack);
            return res.status(500).json({ error: "Database error" });
          }
          return res.json({ message: "User added successfully" });
        });
      } catch (error) {
        console.error("Error hashing password: " + error);
        return res.status(500).json({ error: "Internal server error" });
      }
    }
  );
});

// UPDATE
app.put("/users/:id", upload.single("photo"), (req, res) => {
  const { id } = req.params;
  const { name, email, role } = req.body;
  const photo = req.file ? req.file.filename : null;

  let sql = "UPDATE users SET";
  const values = [];

  if (name) {
    sql += " name = ?,";
    values.push(name);
  }
  if (email) {
    sql += " email = ?,";
    values.push(email);
  }
  if (role) {
    sql += " role = ?,";
    values.push(role);
  }
  if (photo) {
    sql += " photo = ?,";
    values.push(`http://localhost:8000/img/${photo}`);
  }

  sql = sql.slice(0, -1) + " WHERE id = ?";
  values.push(id);

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error("Error updating MySQL: " + err.stack);
      return res.status(500).json({ error: "Database error" });
    }
    return res.json(result);
  });
});

// DELETE
app.delete("/users/:id", (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM users WHERE id = ?", [id], (err, result) => {
    if (err) {
      console.error("Error deleting from MySQL: " + err.stack);
      return res.status(500).json({ error: "Database error" });
    }
    return res.json({ message: "Staff member deleted successfully" });
  });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
