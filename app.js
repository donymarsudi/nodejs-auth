const express = require("express");
const expressEjsLayouts = require("express-ejs-layouts");
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");
const fs = require("fs");
const LocalStrategy = require("passport-local").Strategy; // Import LocalStrategy

const app = express();
const port = 5000;

app.use(expressEjsLayouts);
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));
app.use(express.static("public"));

const users = JSON.parse(fs.readFileSync("data/users.json", "utf-8"));

function saveUsers(users) {
  fs.writeFileSync("data/users.json", JSON.stringify(users, null, 2), "utf-8"); // Ubah path ke "data/users.json"
}

function initializePassport(passport) {
  const authenticateUser = (email, password, done) => {
    const user = users.find((u) => u.email === email);

    if (!user) {
      return done(null, false, { message: "No user with that email" });
    }

    try {
      if (bcrypt.compareSync(password.toString(), user.password.toString())) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Password Incorrect" });
      }
    } catch (e) {
      return done(e);
    }
  };

  passport.use(
    "local",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        passReqToCallback: false, // Ubah menjadi false karena tidak memerlukan req
      },
      authenticateUser // Hanya perlu meneruskan fungsi authenticateUser
    )
  );

  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser((id, done) => {
    return done(
      null,
      users.find((user) => user.id === id)
    );
  });
}
initializePassport(passport);

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    req.user.lastAccess = new Date().toISOString();
    return next();
  }
  res.redirect("/login");
}

app.get("/", (req, res) => {
  res.render("index", {
    layout: "layouts/main-layout.ejs",
  });
});

app.get("/login", (req, res) => {
  const errorMessage = req.flash("error")[0];
  res.render("login.ejs", {
    layout: "layouts/main-layout.ejs",
    message: errorMessage ? errorMessage : "",
  });
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.get("/register", (req, res) => {
  const errorMessage = req.flash("error")[0];
  res.render("register.ejs", {
    layout: "layouts/main-layout.ejs",
    message: errorMessage ? errorMessage : "",
  });
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    req.flash("error", "Please provide name, email, and password");
    return res.status(400).redirect("/register");
  }

  const existingUserByEmail = users.find((user) => user.email === email);
  const existingUserByName = users.find((user) => user.name === name);

  if (existingUserByEmail || existingUserByName) {
    req.flash("error", "Name or email already registered");
    return res.status(400).redirect("/register");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: Date.now().toString(),
      name,
      email,
      password: hashedPassword.toString(),
      registeredAt: new Date().toISOString(),
    };
    users.push(newUser);
    saveUsers(users);
    res.redirect("/login");
  } catch {
    req.flash("error", "Failed to register user"); // Simpan pesan flash
    res.status(500).redirect("/register");
  }
});

app.get("/dashboard", checkAuthenticated, (req, res) => {
  const user = req.user;

  // Cek apakah user sudah login tapi sudah lama tidak mengakses dashboard
  const lastAccessTime = new Date(user.lastAccess);
  const currentTime = new Date();
  const timeDifference = currentTime.getTime() - lastAccessTime.getTime();
  const minutesDifference = Math.floor(timeDifference / 1000 / 60);

  if (minutesDifference > 30) {
    // Jika lebih dari 30 menit, redirect user ke halaman login
    req.flash("error", "Session expired. Please login again.");
    return res.redirect("/login");
  }

  const errorMessage = req.flash("error")[0];
  res.render("dashboard.ejs", {
    layout: "layouts/main-layout.ejs",
    name: user.name,
    message: errorMessage ? errorMessage : "",
  });
});

app.listen(port, () => {
  console.log(`Server Berjalan Di http://localhost:${port}`);
});
