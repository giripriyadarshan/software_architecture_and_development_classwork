const express = require("express");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");

const {
    generateJWTWithPrivateKey, fetchStudents, fetchProfessors,
} = require("./util");
const {ROLES} = require("../../../consts");
const {studentServiceLogger: logger} = require("../../../logging");
const {getCorrelationId} = require("../../../correlationId");

const router = express.Router();

dotenv.config();

// Student Login
router.post("/student", async (req, res) => {
    const {email, password} = req.body;
    logger.debug(`Student login attempt with email: ${email}`);

    try {
        if (!email || !password) {
            logger.warn("Email and password are required for student login");
            return res.status(400).json({
                message: "Email and password are required", correlationId: getCorrelationId()
            });
        }

        //get the list of students
        const students = await fetchStudents();
        const student = students.find((student) => student.email === email);

        if (!student) {
            logger.warn(`Student with email ${email} not found`);
            return res.status(401).json({message: "Invalid email or password", correlationId: getCorrelationId()});
        }

        //compare the password
        const isMatch = await bcrypt.compare(password, student.password);
        if (!isMatch) {
            logger.warn(`Invalid password for student with email ${email}`);
            return res.status(401).json({message: "Invalid email or password", correlationId: getCorrelationId()});
        }

        // Generate JWT
        const token = await generateJWTWithPrivateKey({
            userId: student._id, email: student.email, role: ROLES.STUDENT,
        });
        logger.info(`Student login successful for email: ${email}`);
        res.status(200).json({token});

    } catch (error) {
        logger.error(`Student login error: ${error.message}`);
        res.status(500).json({
            message: "Server error during student login", error: error.message, correlationId: getCorrelationId()
        });
    }
});

// Professor Login
router.post("/professor", async (req, res) => {
    const {email, password} = req.body;
    logger.debug(`Professor login attempt with email: ${email}`);

    try {
        if (!email || !password) {
            logger.warn("Email and password are required for professor login");
            return res
                .status(400)
                .json({message: "Email and password are required", correlationId: getCorrelationId()});
        }

        // Fetch professors
        const professors = await fetchProfessors();
        const professor = professors.find((p) => p.email === email);

        if (!professor) {
            logger.warn(`Professor with email ${email} not found`);
            return res.status(401).json({message: "Invalid email or password", correlationId: getCorrelationId()});
        }

        const isPasswordValid = await bcrypt.compare(password, professor.password);
        if (!isPasswordValid) {
            logger.warn(`Invalid password for professor with email ${email}`);
            return res.status(401).json({message: "Invalid email or password", correlationId: getCorrelationId()});
        }

        // Generate JWT
        const token = await generateJWTWithPrivateKey({
            userId: professor._id, email: professor.email, role: [ROLES.PROFESSOR],
        });
        logger.info(`Professor login successful for email: ${email}`);
        res.status(200).json({token});

    } catch (error) {
        logger.error(`Professor login error: ${error.message}`);
        res.status(500).json({
            message: "Server error during professor login", error: error.message, correlationId: getCorrelationId()
        });
    }
});

module.exports = router;