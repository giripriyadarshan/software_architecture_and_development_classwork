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
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }
    // get the list of students
    const students = await fetchStudents();
    const student = students.find((s) => s.email === email)

    if (!student) {
      return res.status(404).json(
        {
          message: "Student not Found"
        }
      )
    }

    const isMatch = await bcrypt.compare(password, student.password);

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid Credentials"
      })
    }

    const payload = {
      email: student.email,
      roles: [ROLES.STUDENT],
    }
    const token = await generateJWTWithPrivateKey(payload);

    return res.status(200).json({ access_token: token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
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
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
