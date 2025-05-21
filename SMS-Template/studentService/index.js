const express = require('express');
const dotEnv = require('dotenv');
const connectDB = require('./config/db');

const studentRoutes = require('./routes/studentRoute');

// to read the .env file
dotEnv.config();

// initialize express app
const app = express();

// connect to the database
connectDB();

// middleware
app.use(express.json());
app.use("/api/students", studentRoutes);

const PORT = process.env.PORT || 5003;

app.listen(PORT, () => {
    console.log(`studentService is running on port ${PORT}`);
});