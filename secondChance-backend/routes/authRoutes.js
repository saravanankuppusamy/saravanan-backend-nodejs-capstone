const express = require('express');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const connectToDatabase = require('../models/db');
const router = express.Router();
const dotenv = require('dotenv');
const pino = require('pino');  // Import Pino logger
dotenv.config();

const logger = pino();  // Create a Pino logger instance

//Create JWT secret
const JWT_SECRET = process.env.JWT_SECRET;

router.post('/register', async (req, res) => {
    try {
      //Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
      //Task 1
      const db = await connectToDatabase();    
      //Task2     
      const collection = db.collection("users");  
      //Task3      
      const existingEmail = await collection.findOne({ email: req.body.email });

        if (existingEmail) {
            logger.error('Email id already exists');
            return res.status(400).json({ error: 'Email id already exists' });
        }
        //Task4
        const salt = await bcryptjs.genSalt(10);
        const hash = await bcryptjs.hash(req.body.password, salt);
        //Task5
        const email=req.body.email;
        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        });

        //Task6
        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        const authtoken = jwt.sign(payload, JWT_SECRET);
        //Task7
        logger.info('User registered successfully');
        //Task8
        res.json({ authtoken,email });
    } catch (e) {
        logger.error(e);
        return res.status(500).send('Internal server error');
    }
});

//Login Endpoint
router.post('/login', async (req, res) => {
    console.log("\n\n Inside login")

    try {
        //Task1 connect to `secondChance` in MongoDB through `connectToDatabase`
        const db = await connectToDatabase();
        //Task2 Access MongoDB `users` collection
        const collection = db.collection("users");
        //Task3 Check for user credentials in database
        const theUser = await collection.findOne({ email: req.body.email });
        //Task4 Check if the password matches
        if (theUser) {
            let result = await bcryptjs.compare(req.body.password, theUser.password)
            //send appropriate message if mismatch
            if(!result) {
                logger.error('Passwords do not match');
                return res.status(404).json({ error: 'Wrong pasword' });
            }
            
            //Task5 Fetch user details
            const userName = theUser.firstName;
            const userEmail = theUser.email;

            //Task6 Create JWT authentication if passwords match
            let payload = {
                user: {
                    id: theUser._id.toString(),
                },
            };
            const authtoken = jwt.sign(payload, JWT_SECRET);

            logger.info('User logged in successfully');
            return res.status(200).json({ authtoken, userName, userEmail });
        //Task7 Send appropriate message if user not found
        } else {
            logger.error('User not found');
            return res.status(404).json({ error: 'User not found' });
        }
    } catch (e) {
        logger.error(e);
        return res.status(500).json({ error: 'Internal server error', details: e.message });
      }
});

module.exports = router;