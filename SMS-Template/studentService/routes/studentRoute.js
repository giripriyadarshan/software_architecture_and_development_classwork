const express = require("express");

const Student = require("../models/student");

const {verifyRole, restrictStudentToOwnData, jwtRateLimiter} = require("./auth/util");
const {ROLES} = require("../../consts");
const {studentServiceLogger: logger} = require("../../logging");
const {getCorrelationId} = require("../../correlationId");

const router = express.Router();

// POST A NEW STUDENT
router.post("/", async (req, res) => {
    const {name, email, password} = req.body;
    logger.debug(`Query Body: ${req.body}`);

    if (!name || !email || !password) {
        return res.status(400).json({message: "Provide name, email and password"});
    }
    try {
        //check if student exists
        const existingStudent = await Student.findOne({email});
        if (existingStudent) {
            logger.warn(`Student with email ${email} already exists`);
            return res.status(400).json({message: "Student already exists"});
        }
        const newStudent = new Student({name, email, password});
        const savedStudent = await newStudent.save();

        logger.info(`New student created with email: ${email}`);
        return res.status(201).json(savedStudent);
    } catch (error) {
        logger.error(`Error creating student: ${error.message}`);
        return res.status(500).json({
            message: "Unable to create student",
            correlationId: getCorrelationId()
        });

    }
});
//get request for posting students
router.get("/", verifyRole([ROLES.ADMIN, ROLES.AUTH_SERVICE, ROLES.PROFESSOR, ROLES.ENROLLMENT_SERVICE]), jwtRateLimiter, async (req, res) => {
    try {
        let hasAuthServiceRole = false;
        if (Array.isArray(req.user.role)) {
            hasAuthServiceRole = req.user.role.includes(ROLES.AUTH_SERVICE);
        } else if (typeof req.user.role === 'string') {
            hasAuthServiceRole = req.user.role === ROLES.AUTH_SERVICE;
        }
        if (req.user.id === ROLES.AUTH_SERVICE && hasAuthServiceRole) {
            const students = await Student.find();
            logger.info(`Fetched all students by auth service`);
            return res.json(students);
        }
        const students = await Student.find().select("-password");
        logger.info(`Fetched all students`);
        return res.json(students);
    } catch (error) {
        logger.error(`Error fetching students: ${error.message}`);
        return res.status(500).json({
            message: error.message,
            correlationId: getCorrelationId()
        });
    }
});

// GET - Get one student by email
router.get("/:email", async (req, res) => {
    const {email} = req.params;
    try {
        const student = await Student.findOne({email}).select("-password");
        if (!student) {
            logger.warn(`Student with email ${email} not found`);
            return res.status(404).json({message: "Student not found"});
        }
        logger.info(`Fetched student with email: ${email}`);
        return res.status(200).json(student);
    } catch (error) {
        logger.error(`Error fetching student: ${error.message}`);
        return res.status(500).json({
            message: "Unable to find student",
            correlationId: getCorrelationId()
        });
    }
});

// PUT/PATCH - Update student by email
router.put("/:email", verifyRole(ROLES.ADMIN), async (req, res) => {
    const {email} = req.params;
    const {name, password} = req.body;

    if (!name || !password) {
        logger.warn(`Update request missing name or password for email: ${email}`);
        return res.status(400).json({message: "Provide name and password to update"});
    }

    try {
        const updatedStudent = await Student.findOneAndUpdate({email}, {name, email, password}, {
            new: true, runValidators: true
        }).select("-password");
        if (!updatedStudent) {
            logger.warn(`Student with email ${email} not found for update`);
            return res.status(404).json({message: "Student not found"});
        }
        logger.info(`Updated student with email: ${email}`);
        return res.status(200).json(updatedStudent);
    } catch (error) {
        logger.error(`Error updating student: ${error.message}`);
        return res.status(500).json({
            message: "Unable to update student",
            correlationId: getCorrelationId()
        });
    }
});

// PATCH - update particular field/Partial Update
router.patch("/:email", verifyRole(ROLES.ADMIN), async (req, res) => {
    const {email} = req.params;
    try {
        const updatedStudent = await Student.findOneAndUpdate({email}, {$set: req.body}, {
            new: true, runValidators: true
        }).select("-password");
        if (!updatedStudent) {
            logger.warn(`Student with email ${email} not found for partial update`);
            return res.status(404).json({message: "Student not found"});
        }
        logger.info(`Partially updated student with email: ${email}`);
        return res.status(200).json(updatedStudent);
    } catch (error) {
        logger.error(`Error partially updating student: ${error.message}`);
        return res.status(500).json({
            message: "Unable to update student",
            correlationId: getCorrelationId()
        });
    }
});


// DELETE - Remove student by email
router.delete("/:email", verifyRole(ROLES.ADMIN), async (req, res) => {
    const {email} = req.params;
    try {
        const deletedStudent = await Student.findOneAndDelete({email});
        if (!deletedStudent) {
            logger.warn(`Student with email ${email} not found for deletion`);
            return res.status(404).json({message: "Student not found"});
        }
        logger.info(`Deleted student with email: ${email}`);
        return res.status(200).json({message: "Student deleted successfully"});
    } catch (error) {
        logger.error(`Error deleting student: ${error.message}`);
        return res.status(500).json({
            message: "Error deleting student",
            correlationId: getCorrelationId()
        });
    }
});


module.exports = router;
