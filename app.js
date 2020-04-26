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
const Users = mongoose.model("Users", UsersSchema);

app.use(cookieSession({
    name: 'session',
    keys: [0],
  
    // Cookie Options
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }))
app.use(express.urlencoded());
app.set('view engine', 'pug');
app.set('views', './views');

UsersSchema.statics.authenticate = async (email, password) => {
  // buscamos el usuario utilizando el email
  const user = await this.findOne({ email: email });
  if (user) {
    // si existe comparamos la contraseña
    return new Promise((resolve, reject) => {
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) reject(err);
        resolve(result === true ? user : null);
      });
    });
    return user;
  }
  return null;
};

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
  console.log(req.body);
  const user = new Users({ name:name, email:email, password:password });
  await user.save();
  res.redirect('/');
});
 
app.get("/login", (req, res) => { // GET /login - muestra el formulario de autenticación.
    res.render('login');
});
  
app.get("/logout", (req, res) => { //GET /logout - se utiliza para desautenticarse (si esa palabra existe).
    const email = req.body.email;
    Users.deleteOne({ email:email }, function(err) {
        if (err) return console.error(err);
      });
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
      return (e);
    }
});
  
app.listen(3000, () => console.log("Listening on port 3000 ..."));