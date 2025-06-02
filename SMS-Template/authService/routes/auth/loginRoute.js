const express = require("express");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");

const {
  generateJWTWithPrivateKey,
  fetchStudents,
  fetchProfessors,
} = require("./util");
const { ROLES } = require("../../../consts");
 
const router = express.Router();
 
dotenv.config();
 
// Student Login
router.post("/student", async (req, res) => {
  const { email, password } = req.body;
 
  try {
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    //get the list of students
    const students = await fetchStudents();
    const student = students.find((student) => student.email === email);
 
    if (!student) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    //compare the password
    const isMatch = await bcrypt.compare(password, student.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate JWT
    const token = await generateJWTWithPrivateKey({
      userId: student._id,
      email: student.email,
      role: ROLES.STUDENT,
    });
    res.json({ token });

  } catch (error) {
    console.error("Student login error:", error);
    res.status(500).json({ message: "Server error during student login" });
  }
});

// Professor Login
router.post("/professor", async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res
          .status(400)
          .json({ message: "Email and password are required" });
    }

    // Fetch professors
    const professors = await fetchProfessors();
    const professor = professors.find((p) => p.email === email);

    if (!professor) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, professor.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate JWT
    const token = await generateJWTWithPrivateKey({
      userId: professor._id,
      email: professor.email,
      roles: [ROLES.PROFESSOR],
    });
    res.json({ token });

  } catch (error) {
    console.error("Professor login error:", error);
    res.status(500).json({ message: "Server error during professor login" });
  }
});

module.exports = router;