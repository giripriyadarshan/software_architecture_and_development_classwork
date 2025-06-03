const express = require("express");
const dotenv = require("dotenv");
const connectDB = require("./config/db");

const enrollmentRoutes = require("./routes/enrollmentRoute");

const publicKeyRoute = require("./routes/auth/publicKeyRoute");

dotenv.config();

// Initialize express app
const app = express();

// Connect to database
connectDB();

// Middleware
app.use(express.json());

app.use("/.well-known/jwks.json", publicKeyRoute);
app.use("/api/enrollments", enrollmentRoutes);

// Start server
const PORT = process.env.PORT || 5005;
app.listen(PORT, () => {
  console.log(`Enrollment running on port ${PORT}`);
});
