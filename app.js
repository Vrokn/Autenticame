const express = require('express');
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const app = express();
const cookieSession = require('cookie-session');

mongoose.connect(process.env.MONGODB_URL || 'mongodb://localhost:27017/mongo-auth', { useNewUrlParser: true, useUnifiedTopology: true });
mongoose.connection.on("error", function(e) { console.error(e); });

const UsersSchema = new mongoose.Schema({
  name: { type: String },
  email: { type: String },
  password: { type: String },
});

UsersSchema.statics.authenticate = async function (email, password) {
  const user = await this.findOne({ email: email });
  if (user) {
    return new Promise((resolve, reject) => {
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) reject(err);
        resolve(result ? user : null);
      });       
    });
  }  
  return null;
};

const Users = mongoose.model("Users", UsersSchema);

app.use(cookieSession({
    name: 'session',
    keys: ['token'], 
    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }));
app.use(express.urlencoded());
app.set('view engine', 'pug');
app.set('views', './views');
  
const requireUser = async (req, res, next) => {
    const userId = req.session.userId;
    if (userId) {
      const user = await Users.findOne({ _id: userId });
      res.locals.user = user;
      next();
    } else {
      return res.redirect("/login");
    }
  }

app.get("/", requireUser, async (req, res) => { //GET / - muestra la lista de usuarios registrados.
    const users = await Users.find();
    res.render("table", { users: users })
});
  
app.get("/register", (req, res) => { //GET /register - muestra el formulario para registrarse.
    res.render('form');
});

app.post("/register", async (req, res) => { //POST /register - crea al usuario en MongoDB.
  const name = req.body.name;
  const email = req.body.email;
  const password = bcrypt.hashSync(req.body.password, 10);
  const user = new Users({ name:name, email:email, password:password });
  await user.save();
  res.redirect('/');
});
 
app.get("/login", (req, res) => { // GET /login - muestra el formulario de autenticación.
    res.render('login');
});
  
app.get("/logout", (req, res) => { //GET /logout - se utiliza para desautenticarse (si esa palabra existe).
    res.clearCookie("token");       
    res.redirect("/login");
});

app.post("/login", async (req, res) => { //POST /login- autentica al usuario.
    const email = req.body.email;
    const password = req.body.password;  
    try {
      const user = await Users.authenticate(email, password);
      if (user) {
        req.session.userId = user._id; // acá guardamos el id en la sesión
        return res.redirect("/");
      } else {
        res.render("/login", { error: "Wrong email or password. Try again!" });
      }
    } catch (e) {
      return res.status(500).send(e); 
    }
});
  
app.listen(3000, () => console.log("Listening on port 3000 ..."));