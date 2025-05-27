
 
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
 
    //return res.status(200).json({students}); // Verification
    //Generate JWT Token
    const payload = {id: student._id, role: [ROLES.STUDENT]};
    const token = generateJWTWithPrivateKey ({payload});
    return res.status(200).json({accessToken: token});
 
    } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});
 
/*// Professor Login
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
}); */
 
//Professor Login
router.post("/professor", async (req, res) => {
  const { email, phone, password } = req.body;
 
  try {
    if (!email ||!phone || !password) {
      return res.status(400).json({ message: "Email and Phone and password are required" });
    }
 
    //get the list of professors
    const professors = await fetchProfessors();
    const professor = professors.find((professor) => professor.email === email);
 
    if (!professor) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
 
    //compare the password
    const isMatch = await bcrypt.compare(password, professor.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
 
    //return res.status(200).json({professors}); // Verification
    //Generate JWT Token
    const payload = {id: professor._id, role: [ROLES.PROFESSOR]};
    const token = generateJWTWithPrivateKey ({payload});
    return res.status(200).json({accessToken: token});
 
    } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Server error" });
  }
});
 
module.exports = router;
 
 
 
 