import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import env from "dotenv";
import passport from "passport";
import { Strategy } from "passport-local";

env.config();
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = process.env.SALT_ROUNDS;

app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static("public"));

app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DB,
});
db.connect();

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("login");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    res.redirect("/");
  });
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    //Check if user exist before accepting the details
    const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);
    if (checkUser.rows.length > 0) {
      res.send("User already exist, try loggin in");
    } else {
      //Hash user's password and store it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log(err);
        } else {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1,$2) RETURNING *",
            [username, hash]
          );
          const user = newUser.rows[0];
          console.log(user);
          req.login(user, (err) => {
            console.log(err);
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      //Check if user exist in the database
      const checkUser = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);

      if (checkUser.rows.length > 0) {
        const user = checkUser.rows[0];
        const hashedPassword = user.password;
        // Validate password before rendering page
        bcrypt.compare(password, hashedPassword, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(err, user);
            } else {
              return cb(err, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (error) {
      return cb(error);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () =>
  console.log(`Server listening on http://localhost:${port}`)
);
