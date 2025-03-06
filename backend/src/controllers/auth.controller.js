import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs";

export const signup = async (req, res) => {
	const { email, fullName, password } = req.body;
	try {
		if (!email || !fullName || !password) {
			return res.status(400).send({
				message: "Please fill all fields",
			});
		}

		if (password.length < 6) {
			return res.status(400).send({
				message: "Password must be at least 6 characters",
			});
		}

		const user = await User.findOne({ email });

		if (user) {
			return res.status(400).send({ message: "User already exists" });
		}

		const salt = await bcrypt.genSalt(10);
		const hashedPassword = await bcrypt.hash(password, salt);

		const newUser = new User({
			email,
			fullName,
			password: hashedPassword,
		});

		if (newUser) {
			generateToken(newUser._id, res);
			await newUser.save();
			res.status(201).json({
				_id: newUser._id,
				email: newUser.email,
				fullName: newUser.fullName,
				profilePicture: newUser.profilePicture,
			});
		} else {
			res.status(400).send({ message: "Invalid user data" });
		}
	} catch (error) {
		console.log("Error in signup Controller", error);
		res.status(500).send({ message: "Internal Server Error" });
	}
};

export const login = async (req, res) => {
	const { email, password } = req.body;
	try {
		const user = await User.findOne({ email });
		if (!user) {
			return res.status(400).send({ message: "Invalid credentials" });
		}

		const isPasswordCorrect = await bcrypt.compare(password, user.password);
		if (!isPasswordCorrect) {
			return res.status(400).send({ message: "Invalid credentials" });
		}

		generateToken(user._id, res);
		res.status(200).json({
			_id: user._id,
			email: user.email,
			fullName: user.fullName,
			profilePicture: user.profilePicture,
		});
	} catch (error) {
		console.log("Error in login Controller", error);
		res.status(500).send({ message: "Internal Server Error" });
	}
};

export const logout = (req, res) => {
	res.send("Logout route");
};
