import express from 'express';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import twilio from 'twilio';
import crypto from 'crypto';
import http from 'http'; 
import { Server as WebSocketServer } from 'socket.io';

dotenv.config();

const app = express();
const server = http.createServer(app);

const port = process.env.PORT || 4000;
mongoose.connect(process.env.MONGODB_URI, { 
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const User = mongoose.model('User', {
  username: String,
  phone: String,
  password: String,
  verificationCode: String,
  isVerified: Boolean,
});

function generateVerificationCode() {
  const code = crypto.randomBytes(4).toString('hex').toUpperCase();
  return code;
}

const viritualPhone = '+14787072893';
const accountSid = 'AC50a2befd063627eb16b1216d0644e702';
const authToken = 'a10f5b14fa581ce53ebdf04b401fc692';
const client = twilio(accountSid, authToken);

async function sendVerificationCode(phoneNumber, code) {
  try {
    const message = await client.messages.create({
      body: `Your verification code is: ${code}`,
      from: viritualPhone,
      to: phoneNumber,
    });
    console.log('Verification code sent:', message.sid);
  } catch (error) {
    console.error('Error sending verification code:', error);
  }
}

app.use(bodyParser.json());

let userData = [];

app.post('/register', async (req, res) => {
  try {
    const { username, phone, password } = req.body;

    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким номером уже зарегистрирован' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = generateVerificationCode();
    const user = new User({
      username,
      phone,
      password: hashedPassword,
      verificationCode,
      isVerified: false,
    });
    await user.save();

    await sendVerificationCode(user.phone, user.verificationCode);

    
    res.status(201).json({ message: 'Пользователь успешно зарегистрирован', data: user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/verify', async (req, res) => {
  try {
    const { phone, verificationCode } = req.body;
    const user = await User.findOne({ phone });

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.verificationCode !== verificationCode) {
      return res.status(401).json({ error: 'Invalid verification code' });
    }

    user.isVerified = true;
    await user.save();

    res.status(200).json({ message: 'Verification successful' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    console.log(req.body)
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(401).json({ error: 'Authentication failed' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Authentication failed' });
    }
    const token = jwt.sign({ userId: user._id }, 'islamaibekov2005evion', { expiresIn: '1h' });
    userData.push(user)
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Authentication failed' });
  }
});

app.get('/profile', async (req, res) => {
  try {
    res.status(200).json({ userData });
  } catch (error) {
    console.log(error);
  }
});


server.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
