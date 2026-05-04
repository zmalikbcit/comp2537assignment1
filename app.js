require('dotenv').config();

// Warn early if critical env vars are missing
const requiredEnv = ['MONGODB_USER', 'MONGODB_PASSWORD', 'MONGODB_HOST', 'MONGODB_DATABASE', 'NODE_SESSION_SECRET', 'MONGODB_SESSION_SECRET'];
requiredEnv.forEach((key) => {
    if (!process.env[key]) console.warn(`WARNING: Missing environment variable: ${key}`);
});

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const { database } = require('./databaseConnection');

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 12;

// Session expiry: 1 hour
const expireTime = 1 * 60 * 60 * 1000;

// Required for Render — tells Express it's sitting behind a reverse proxy
app.set('trust proxy', 1);

// middleware
app.use(express.urlencoded({ extended: false }));

// Build MongoStore options — crypto is only added when the secret is a non-empty string.
// connect-mongo crashes at store creation (not at request time) if crypto.secret is
// null or undefined, so we must not pass the crypto key at all in that case.
const mongoStoreOptions = {
    mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/?retryWrites=true`,
    dbName: 'sessions',
};
if (process.env.MONGODB_SESSION_SECRET && process.env.MONGODB_SESSION_SECRET.length > 0) {
    mongoStoreOptions.crypto = { secret: process.env.MONGODB_SESSION_SECRET };
}

app.use(
    session({
        secret: process.env.NODE_SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        store: MongoStore.create(mongoStoreOptions),
        cookie: {
            maxAge: expireTime,
            // Only use secure/sameSite:none on production (Render sets NODE_ENV=production)
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        },
    })
);

app.use(express.static(__dirname + '/public'));

// helper
function isLoggedIn(req) {
    return req.session && req.session.authenticated;
}

// home
app.get('/', (req, res) => {
    if (!isLoggedIn(req)) {
        res.send(`
      <h1>Welcome</h1>
      <a href="/signup"><button>Sign up</button></a><br><br>
      <a href="/login"><button>Log in</button></a>
    `);
    } else {
        res.send(`
      <h1>Hello, ${req.session.name}!</h1>
      <a href="/members"><button>Go to Members Area</button></a><br><br>
      <a href="/logout"><button>Logout</button></a>
    `);
    }
});

// signup get
app.get('/signup', (req, res) => {
    res.send(`
    <h2>create user</h2>
    <form method="POST" action="/signupSubmit">
      <input name="name" type="text" placeholder="name" /><br>
      <input name="email" type="email" placeholder="email" /><br>
      <input name="password" type="password" placeholder="password" /><br>
      <button type="submit">Submit</button>
    </form>
  `);
});

// signupSubmit post
app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name) {
        return res.send(`Name is required.<br><a href="/signup">Try again</a>`);
    }
    if (!email) {
        return res.send(`Email is required.<br><a href="/signup">Try again</a>`);
    }
    if (!password) {
        return res.send(`Password is required.<br><a href="/signup">Try again</a>`);
    }

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required(),
    });

    const { error } = schema.validate({ name, email, password });
    if (error) {
        return res.send(`Invalid input.<br><a href="/signup">Try again</a>`);
    }

    const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name, email, password: hashedPassword });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    req.session.save((err) => {
        if (err) {
            console.error('Session save error:', err);
        }
        res.redirect('/members');
    });
});

// login get
app.get('/login', (req, res) => {
    res.send(`
    <h2>log in</h2>
    <form method="POST" action="/loginSubmit">
      <input name="email" type="email" placeholder="email" /><br>
      <input name="password" type="password" placeholder="password" /><br>
      <button type="submit">Submit</button>
    </form>
  `);
});

// loginSubmit post
app.post('/loginSubmit', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required(),
    });

    const { error } = schema.validate({ email, password });
    if (error) {
        return res.redirect('/login');
    }

    const userCollection = database.db(process.env.MONGODB_DATABASE).collection('users');
    const users = await userCollection.find({ email }).toArray();

    if (users.length === 0) {
        return res.send(`Invalid email/password combination.<br><a href="/login">Try again</a>`);
    }

    const user = users[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
        return res.send(`Invalid email/password combination.<br><a href="/login">Try again</a>`);
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.cookie.maxAge = expireTime;

    req.session.save((err) => {
        if (err) {
            console.error('Session save error:', err);
        }
        res.redirect('/members');
    });
});

// Members get
app.get('/members', (req, res) => {
    if (!isLoggedIn(req)) {
        return res.redirect('/');
    }

    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
    <h1>Hello, ${req.session.name}.</h1>
    <img src="/${randomImage}" style="max-width:400px;" /><br><br>
    <a href="/logout"><button>Sign out</button></a>
  `);
});

// Logout get
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// 404 Catch all
app.get('*', (req, res) => {
    res.status(404).send('Page not found - 404');
});

// Start Server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});