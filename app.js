import express from 'express';
import bodyParser from 'body-parser';
import userRouter from "./router/user.router.js" ;
import mongoose from 'mongoose' ;
import User from "./model/user.model.js"
import bcrypt from "bcryptjs" ;
import jwt from "jsonwebtoken" ;
import cors from "cors" ;
import { verify } from "./authenticate.js"
import Joi from 'joi'; // Import Joi for validation

const app = express();
app.use(cors());
app.use(bodyParser.json()); // For parsing application/json
app.use(bodyParser.urlencoded({ extended: true }));

const port = 3000;

const mongoURI = 'mongodb+srv://riyatout:LivnvEuaeIQnmwb2@cluster0.kiyt1.mongodb.net/demo?retryWrites=true&w=majority&appName=Cluster0';

// Connect to MongoDB Atlas
mongoose.connect(mongoURI)
  .then(() => {
    console.log('Connected to MongoDB Atlas');
  })
  .catch(err => {
    console.error('Error connecting to MongoDB Atlas:', err);
  });

// Validation schemas
const signupSchema = Joi.object({
  name: Joi.string().min(3).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const signinSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const updateSchema = Joi.object({
  oldEmail: Joi.string().email().required(),
  newEmail: Joi.string().email().required(),
});

// Signup route
app.post('/signup', async (req, res) => {
  const { error } = signupSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  try {
    const saltKey = await bcrypt.genSalt(10);
    let encryptPassword = await bcrypt.hash(req.body.password, saltKey);
    req.body.password = encryptPassword;
    const user = new User(req.body);
    await user.save();
    res.status(201).json({ user: user, message: 'Signup successful' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Signin route
app.post('/signin', async (req, res) => {
  const { error } = signinSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    let status = await bcrypt.compare(req.body.password, user.password);
    if (status) {
      const token = jwt.sign({ id: user._id, email: user.email }, 'secretkey');
      return res.status(200).json({ user: user, message: "Sign-in successful", token: token });
    }
    return res.status(401).json({ message: "Wrong credentials" });
  } catch (error) {
    return res.status(500).json({ message: "Internal server error", error: error.message });
  }
});

// Update route
app.post('/update', verify, async (req, res) => {
  const { error } = updateSchema.validate(req.body);
  if (error) return res.status(400).json({ message: error.details[0].message });

  try {
    const { oldEmail, newEmail } = req.body;
    const user = await User.findOne({ email: oldEmail });
    if (user) {
      await User.updateOne({ email: oldEmail }, { $set: { email: newEmail } });
      return res.status(200).json({ message: "User updated successfully" });
    }
    return res.status(404).json({ message: "User not found" });
  } catch (error) {
    return res.status(500).json({ message: "Internal server error", error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
