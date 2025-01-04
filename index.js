import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import env from "dotenv";
import ejs from "ejs";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
  });
  db.connect();


app.use(bodyParser.urlencoded({extended: true}));

app.use(express.static("public"));

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }, 
    })
);

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
    console.log("Session:", req.session);
    console.log("User:", req.user);
    next();
});

app.get("/", (req,res) =>{
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) return next(err);
        req.session.destroy(() => {
            res.redirect("/");
        });
    });
});

app.get("/dashboard.html", (req,res) => {
    if(req.isAuthenticated()){
      console.log("User is authenticated:", req.user);
      res.render("dashboard.ejs");
    } else {
      console.log("User is not authenticated");
      res.redirect("/login");
    }
});

app.post(
    "/login",
    passport.authenticate("local", {
      successRedirect: "/dashboard.html",
      failureRedirect: "/login",
    }), (req, res) => {
        if (req.user) {
            req.session.user_id = req.user.id; 
          }
        res.redirect("/dashboard.html");
      }
);

app.post("/register", async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
  
    try {
      const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
        email,
      ]);
  
      if (checkResult.rows.length > 0) {
        res.redirect("/login");
      } else {
        bcrypt.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            console.error("Error hashing password:", err);
            res.status(500).send("Error registering user");
          } else {
            const result = await db.query(
              "INSERT INTO users (name,email, password) VALUES ($1, $2,$3) RETURNING *",
              [name,email, hash]
            );
            const user = result.rows[0];
            req.login(user, (err) => {
                if (err) {
                  console.error("Error logging in after registration:", err);
                  res.status(500).send("Error logging in");
                } else {
                  res.redirect("/dashboard.html");
                }
              });
          }
        });
      }
    } catch (err) {
      console.log(err);
    }
});

passport.use(
    new Strategy({ usernameField: "email" }, async function verify(email, password, cb) {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
          email,
        ]);
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;

          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
            if (err) {
              console.error("Error comparing passwords:", err);
              return cb(err);
            } else {
              if (valid) {
                console.log("Password is valid");
                return cb(null, user);
              } else {
                console.log("Invalid password");
                return cb(null, false);
              }
            }
          });
        } else {
          return cb("User not found");
        }
      } catch (err) {
        console.log(err);
      }
    })
);

app.get("/waste-log.html", (req,res) => {
    res.render("waste-log.ejs");
});

app.post("/waste-log.html", async (req,res) => {
    if (!req.isAuthenticated()) {
        return res.redirect("/login");
      }

    const { wasteType, amount, logDate } = req.body;
    const userId = req.user.id;

    try {
        const result = await db.query(
            `INSERT INTO wastelog (user_id, type, quantity, date, created_at) 
             VALUES ($1, $2, $3, $4, NOW()) 
             RETURNING id`,
            [userId, wasteType, amount, logDate]
        );

        res.redirect('/dashboard.html'); 
    } catch (err) {
        console.error('Error logging waste:', err.message);
        res.status(500).send('An error occurred while logging waste.');
    }
});

app.get('/track-waste.html', async (req, res) => {
    const userId = req.user?.id;
    if (!userId) {
        return res.status(403).send('Unauthorized: Please log in first.');
        res.send("<a href='/login'>Login</a>");
    }

    try {
        const result = await db.query(
            `SELECT id, type, quantity, date FROM wastelog WHERE user_id = $1 ORDER BY date DESC`,
            [userId]
        );
        res.render('track-waste.ejs', { wasteLogs: result.rows });
    } catch (err) {
        console.error('Error fetching waste logs:', err.message);
        res.status(500).send('An error occurred while fetching your waste logs.');
    }
});

app.post('/update-waste.html', async (req, res) => {
    const { id, type, quantity, date } = req.body;

    try {
        await db.query(
            `UPDATE wastelog SET type = $1, quantity = $2, date = $3 WHERE id = $4`,
            [type, quantity, date, id]
        );
        res.redirect('/track-waste.html');
    } catch (err) {
        console.error('Error updating waste log:', err.message);
        res.status(500).send('An error occurred while updating the waste log.');
    }
});

app.delete('/delete-waste.html/:id', async (req, res) => {
    const logId = req.params.id;

    try {
        await db.query(`DELETE FROM wastelog WHERE id = $1`, [logId]);
        res.status(200).send('Log deleted successfully');
    } catch (err) {
        console.error('Error deleting waste log:', err.message);
        res.status(500).send('An error occurred while deleting the waste log.');
    }
});
  
passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
      if (result.rows.length > 0) {
        cb(null, result.rows[0]); 
      } else {
        cb(new Error("User not found"));
      }
    } catch (err) {
      cb(err);
    }
  });


app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });