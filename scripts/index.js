import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import env from "dotenv";
import ejs from "ejs";

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
        secret: 'your-secret-key',
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }, 
    })
);

app.get("/", (req,res) =>{
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.get("/dashboard", (req, res) => {
    res.render("dashboard.ejs");
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
  });