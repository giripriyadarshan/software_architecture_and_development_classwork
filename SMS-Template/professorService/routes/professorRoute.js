const express = require("express");
const Professor = require("../models/professor");
const bcrypt = require("bcrypt");
const {verifyRole, restrictProfessorToOwnData, jwtRateLimiter} = require("./auth/util");
const {ROLES} = require("../../consts");
const {studentServiceLogger: logger} = require("../../logging");
const {getCorrelationId} = require("../../correlationId");

const router = express.Router();

// Create a new professor
router.post("/", verifyRole([ROLES.ADMIN]), async (req, res) => {
    try {
        logger.debug(`Query Body: ${req.body}`);
        const {name, email, phone, password} = req.body;

        // Ensure all fields are provided
        if (!name || !email || !phone || !password) {
            logger.warn("All fields are required for creating a professor");
            return res.status(400).json({message: "All fields are required", correlationId: getCorrelationId()});
        }

        // Check for duplicate email or phone
        const existingProfessor = await Professor.findOne({
            $or: [{email}, {phone}],
        });
        if (existingProfessor) {
            logger.warn(`Professor with email ${email} or phone ${phone} already exists`);
            return res.status(409).json({message: "Email or phone already exists", correlationId: getCorrelationId()});
        }

        // Create and save the professor
        const professor = new Professor({name, email, phone, password});
        await professor.save();

        logger.info(`New professor created with email: ${email}`);
        res
            .status(201)
            .json({message: "Professor created successfully", professor});
    } catch (error) {
        console.error(error);
        res.status(500).json({message: "Server Error", error: error.message});
    }
});

// Get all professors
router.get("/", verifyRole([ROLES.ADMIN, ROLES.AUTH_SERVICE, ROLES.ENROLLMENT_SERVICE]), jwtRateLimiter, async (req, res) => {
    try {
        let hasAuthServiceRole = false;
        if (Array.isArray(req.user.role)) {
            hasAuthServiceRole = req.user.role.includes(ROLES.AUTH_SERVICE);
        } else if (typeof req.user.role === 'string') {
            hasAuthServiceRole = req.user.role === ROLES.AUTH_SERVICE;
        }
        if (req.user.id === ROLES.AUTH_SERVICE && hasAuthServiceRole) {
            const professors = await Professor.find();
            logger.info(`Fetched all professors by auth service`);
            return res.status(200).json(professors);
        }
        const professors = await Professor.find().select("-password"); // Exclude password
        logger.info(`Fetched all professors`);
        return res.status(200).json(professors);
    } catch (error) {
        logger.error(`Error fetching professors: ${error.message}`);
        res.status(500).json({message: "Server Error", error: error.message, correlationId: getCorrelationId()});
    }
});

// Get a specific professor by ID
router.get("/:email", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), restrictProfessorToOwnData, async (req, res) => {
    try {
        const {email} = req.params;
        const professor = await Professor.findOne({email}).select("-password");

        if (!professor) {
            logger.warn(`Professor with email ${email} not found`);
            return res.status(404).json({message: "Professor not found", correlationId: getCorrelationId()});
        }

        logger.info(`Fetched professor with email: ${email}`);
        res.status(200).json(professor);
    } catch (error) {
        if (error.kind === "ObjectId") {
            logger.warn(`Invalid professor ID format: ${req.params.email}`);
            return res.status(400).json({message: "Invalid professor ID format", correlationId: getCorrelationId()});
        }
        logger.error(`Error fetching professor: ${error.message}`);
        res.status(500).json({message: "Server Error", error: error.message, correlationId: getCorrelationId()});
    }
});

// Update a professor
router.put("/:emailParam", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), restrictProfessorToOwnData, async (req, res) => {
    try {
        const {emailParam} = req.params;
        const {name, email, phone, password} = req.body;

        const updatedData = {name, email, phone};
        if (password) {
            const salt = await bcrypt.genSalt(10);
            updatedData.password = await bcrypt.hash(password, salt);
        }

        const professor = await Professor.findOneAndUpdate({email: emailParam}, updatedData, {
            new: true,
        });

        if (!professor) {
            logger.warn(`Professor with email ${emailParam} not found for update`);
            return res.status(404).json({message: "Professor not found", correlationId: getCorrelationId()});
        }

        logger.info(`Updated professor with email: ${emailParam}`);
        res
            .status(200)
            .json({message: "Professor updated successfully", professor});
    } catch (error) {
        if (error.kind === "ObjectId") {
            logger.warn(`Invalid professor ID format: ${req.params.emailParam}`);
            return res.status(400).json({message: "Invalid professor ID format", correlationId: getCorrelationId()});
        }
        res.status(500).json({message: "Server Error", error: error.message, correlationId: getCorrelationId()});
    }
});

// Delete a professor
router.delete("/:email", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), restrictProfessorToOwnData, async (req, res) => {
    try {
        const {email} = req.params;
        const professor = await Professor.findOneAndDelete({email});

        if (!professor) {
            logger.warn(`Professor with email ${email} not found for deletion`);
            return res.status(404).json({message: "Professor not found", correlationId: getCorrelationId()});
        }

        logger.info(`Deleted professor with email: ${email}`);
        res
            .status(200)
            .json({message: "Professor deleted successfully", professor});
    } catch (error) {
        if (error.kind === "ObjectId") {
            logger.warn(`Invalid professor ID format: ${req.params.email}`);
            return res.status(400).json({message: "Invalid professor ID format", correlationId: getCorrelationId()});
        }
        logger.error(`Error deleting professor: ${error.message}`);
        res.status(500).json({message: "Server Error", error: error.message, correlationId: getCorrelationId()});
    }
});

module.exports = router;
