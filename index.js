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

app.get('/trends.html', async (req, res) => {
    const userId = req.user?.id;

    const wasteLogs = await db.query(
        `SELECT type, SUM(quantity) AS quantity, date
         FROM wastelog
         WHERE user_id = $1
         GROUP BY type, date
         ORDER BY date`,
        [userId]
      );

    try {
      const typeGroupedData = await db.query(
        `SELECT type, SUM(quantity) AS quantity
         FROM wastelog
         WHERE user_id = $1
         GROUP BY type`,
        [userId]
      );
      const dateGroupedData = await db.query(
        `SELECT
                TO_CHAR(date, 'YYYY-MM') AS month,
                SUM(quantity) AS quantity
            FROM wastelog
            WHERE user_id = $1
            GROUP BY month
            ORDER BY month`,
        [userId]
      );

      const weekGroupedData = await db.query(
        `SELECT type, SUM(quantity) AS quantity, date
         FROM wastelog
         WHERE user_id = $1
         GROUP BY type, date
         ORDER BY date`,
        [userId]
      );
  
      const dayOfWeekGroupedData = Array(7).fill(0); 
      weekGroupedData.rows.forEach(log => {
        const dayOfWeek = new Date(log.date).getDay(); 
        dayOfWeekGroupedData[dayOfWeek] += parseFloat(log.quantity);
      });
  
      console.log("Aggregated Waste by Type:", typeGroupedData.rows);
      console.log("Aggregated Waste by Date:", dateGroupedData.rows);
  
      res.render('trends.ejs', { 
        typeGroupedData: typeGroupedData.rows, 
        dateGroupedData: dateGroupedData.rows, dayOfWeekGroupedData
      });
  
    } catch (error) {
      console.error("Error fetching waste logs:", error);
      res.status(500).send("Error fetching waste logs.");
    }
});

app.get('/recommendations.html', async (req, res) => {
    try {
      const userId = req.user?.id;
      const result = await db.query('SELECT DISTINCT type FROM wastelog WHERE user_id = $1',[userId]);

      const loggedWastes = result.rows.map(row => row.type);
  
      // Prepare suggestions for the logged waste types
      const recommendations = loggedWastes.map(wasteType => {
        return {
          wasteType,
          suggestions: wasteSuggestions[wasteType] || {}
        };
      });
  
      // Render the recommendations page with the data
      res.render('recommendation.ejs', { recommendations });
  
    } catch (error) {
      console.error(error);
      res.status(500).send('Error fetching waste logs');
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


  const wasteSuggestions = {
    Plastic: {
      suggestion1: "Minimize single-use plastics by choosing reusable items like bags, bottles, and containers.",
      suggestion2: "Opt for products with minimal plastic packaging.",
      suggestion3: "Repurpose plastic containers for storage or organization.",
      suggestion4: "Use plastic bottles as planters or for DIY crafts.",
      suggestion5: "Recycle plastic bottles, containers, and packaging according to local recycling guidelines."
    },
    Paper: {
      suggestion1: "Use both sides of paper before discarding.",
      suggestion2: "Switch to digital documents instead of printing whenever possible.",
      suggestion3: "Use old newspapers or magazines for packaging material.",
      suggestion4: "Repurpose scrap paper for notes or crafts.",
      suggestion5: "Recycle paper products like newspapers, cardboard, and office paper."
    },
    Metal: {
      suggestion1: "Buy items with less metal packaging, such as reusable containers or products in cardboard packaging.",
      suggestion2: "Reduce the consumption of metal items like cans by switching to alternatives.",
      suggestion3: "Repurpose metal cans as planters or storage containers.",
      suggestion4: "Use metal scraps for DIY projects or artwork.",
      suggestion5: "Recycle metals like aluminum and steel, ensuring they are cleaned before recycling."
    },
    Organic: {
      suggestion1: "Minimize food waste by planning meals and buying only what you need.",
      suggestion2: "Opt for organic food to support sustainable farming.",
      suggestion3: "Use food scraps for composting to enrich soil.",
      suggestion4: "Repurpose vegetable scraps for broths or smoothies.",
      suggestion5: "Compost organic waste instead of sending it to a landfill."
    },
    Glass: {
      suggestion1: "Choose glass containers over plastic ones.",
      suggestion2: "Opt for reusable glass bottles or jars.",
      suggestion3: "Repurpose glass jars as storage containers, vases, or candle holders.",
      suggestion4: "Use broken glass pieces for mosaics or creative crafts.",
      suggestion5: "Recycle glass containers by rinsing them before placing them in the recycling bin."
    },
    Textile: {
      suggestion1: "Buy fewer clothing items by choosing timeless, durable pieces.",
      suggestion2: "Avoid fast fashion and opt for sustainable brands.",
      suggestion3: "Donate or sell old clothes to extend their life cycle.",
      suggestion4: "Repurpose old clothes into cleaning rags or quilts.",
      suggestion5: "Recycle textiles through specialized textile recycling programs."
    },
    Electronics: {
      suggestion1: "Extend the lifespan of electronics by repairing or upgrading instead of replacing.",
      suggestion2: "Donate old electronics that are still in working condition.",
      suggestion3: "Recycle electronics at designated e-waste recycling centers.",
      suggestion4: "Avoid throwing away batteries and recycle them through proper channels.",
      suggestion5: "Buy electronics with longer lifespans and avoid planned obsolescence."
    },
    Hazardous: {
      suggestion1: "Handle hazardous materials with care and dispose of them at certified hazardous waste facilities.",
      suggestion2: "Avoid buying hazardous products like certain cleaning supplies or batteries when possible.",
      suggestion3: "Check for safer, non-toxic alternatives for everyday products.",
      suggestion4: "Recycle or properly dispose of used paints, pesticides, or chemicals.",
      suggestion5: "Avoid mixing hazardous waste with regular waste to prevent contamination."
    },
    Construction: {
      suggestion1: "Reduce the amount of construction waste by planning projects carefully.",
      suggestion2: "Reuse materials like wood, metal, and bricks from old buildings.",
      suggestion3: "Donate or sell salvageable construction materials.",
      suggestion4: "Recycle concrete, asphalt, and other construction debris.",
      suggestion5: "Consider sustainable building practices and use eco-friendly materials."
    },
    Medical: {
      suggestion1: "Minimize the use of single-use medical products by opting for reusable or biodegradable alternatives.",
      suggestion2: "Properly dispose of medical waste such as syringes and expired medications at designated collection points.",
      suggestion3: "Donate unused medical supplies to hospitals or charitable organizations.",
      suggestion4: "Avoid flushing medications or chemicals down the drain.",
      suggestion5: "Recycle medical packaging where possible and follow local disposal guidelines."
    }
};
  