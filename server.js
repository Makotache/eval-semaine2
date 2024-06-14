import express from "express";
import path from 'node:path';
import session from 'express-session';
import routes from "./routes/index.js";
import dotenv from 'dotenv';
import MongoStore from "connect-mongo";
import flash from "express-flash";
dotenv.config();

const server = express();
const port = 8000;

const __dirname = import.meta.url.replace("server.js", "");
const staticPath = path.join(__dirname, 'public').replaceAll("%20", " ").replace("file:\\", "");

server.set('view engine', "pug");
server.use(session({
    name: "test",
    secret: "simple",
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URL })
}));

server.use(function (req, res, next)
{
    res.locals.message = req.session.message
    req.session.message = null
    next();
});
server.use(flash())
server.use(express.static(staticPath));
server.use(express.urlencoded({ extended: false }));
server.use(routes);


server.listen(port, () =>
{
    console.log(`Listening on port ${port}`);
});