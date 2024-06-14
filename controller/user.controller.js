import UserModel from '../model/user.js'
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config()

function validateEmail(email)
{
	const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
	return emailRegex.test(email);
}


export function registerGet(req, res)
{
	res.render("user/register", { info: req.flash("info"), errors: req.flash("error") });
}

export async function registerPost(req, res)
{
	const { firstname, lastname, email, password, password_repeat } = req.body;

	const all_error = [];

	if (firstname == "" || lastname == "" || email == "" || password == "" || password_repeat == "")
	{ all_error.push("All fields must be fill."); }

	if (!validateEmail(email))
	{ all_error.push("The email has an incorrect format.") }

	if (password != password_repeat)
	{ all_error.push("Passwords do not match.") }


	const user = await UserModel.findOne({ email: email });
	if (user)
	{ all_error.push("The email already used.") }

	if (all_error.length > 0)
	{
		req.flash("error", all_error);
		res.redirect("/user/register");
		return;
	}

	const hasher = crypto.createHmac("sha256", process.env.HMAC_SECRET);
	const hashed_password = hasher.update(password).digest("hex");

	const newUser = new UserModel({
		firstname,
		lastname,
		email,
		password: hashed_password
	})

	await newUser.save();
	req.flash("success", "You have been registered.")
	res.redirect("/user/login")
}

export function loginGet(req, res)
{
	res.render("user/login", { success: req.flash("success"), errors: req.flash("error") });
}

export async function loginPost(req, res)
{
	const { email, password } = req.body;

	const all_error = [];

	const hasher = crypto.createHmac("sha256", process.env.HMAC_SECRET);
	const hashed_password = hasher.update(password).digest("hex");

	const user = await UserModel.findOne({ email, password: hashed_password });

	if (!user)
	{ all_error.push("There was a problem with the email or password.") }

	if (all_error.length > 0)
	{
		req.flash("error", all_error)
		res.render("user/login");
		return;
	}

	req.flash("success", "You have been logged.")
	req.session.auth = user;
	res.redirect("/user/dashboard");
}

export function logout(req, res)
{
	req.session.auth = null; //destro empêche flash de fonctionner
	//req.session.destroy(); 
	req.flash("info", "You have been disconnected.");
	res.redirect("/user/register");
}

export function dashboard(req, res)
{
	res.render("user/dashboard", { user: req.session.auth, success: req.flash("success") });
}

