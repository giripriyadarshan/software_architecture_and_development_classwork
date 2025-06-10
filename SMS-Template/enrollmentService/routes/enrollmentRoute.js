const express = require("express");

const Enrollment = require("../models/enrollment");

const router = express.Router();

const {
    verifyRole, restrictStudentToOwnData, fetchStudents, fetchCourses, jwtRateLimiter
} = require("./auth/util");
const {ROLES} = require("../../consts");

const {enrollmentServiceLogger: logger} = require("../../logging");
const {getCorrelationId} = require("../../correlationId");

// Create a new enrollment
router.post("/", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        const {student, course} = req.body;

        // Ensure both student and course IDs are provided
        if (!student || !course) {
            logger.warn("Student and Course are required for enrollment");
            return res
                .status(400)
                .json({message: "Student and Course are required", correlationId: getCorrelationId()});
        }
        const students = await fetchStudents();
        const existingStudent = students.find(s => s._id === student);
        if (!existingStudent) {
            logger.warn(`Student with ID ${student} does not exist`);
            return res.status(404).json({message: "Student does not exist", correlationId: getCorrelationId()});
        }

        const courses = await fetchCourses();
        const existingCourse = courses.find(s => s._id === course);
        if (!existingCourse) {
            logger.warn(`Course with ID ${course} does not exist`);
            return res.status(404).json({message: "Course does not exist", correlationId: getCorrelationId()});
        }

        const enrollment = new Enrollment({student, course});
        await enrollment.save();

        logger.info(`Enrollment created successfully for student ${student} in course ${course}`);
        return res.status(200).json(enrollment);
    } catch (error) {
        logger.error(`Error creating enrollment: ${error.message}`);
        res.status(500).json({
            message: "Server Error: Unable to create enrollment",
            error: error.message,
            correlationId: getCorrelationId()
        });
    }
});
// Get all enrollments
router.get("/", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), jwtRateLimiter, async (req, res) => {
    try {
        let enrollments = await Enrollment.find();
        logger.info(`Fetched all enrollments successfully`);
        res.status(200).json(enrollments);
    } catch (error) {
        logger.error(`Error fetching enrollments: ${error.message}`);
        res.status(500).json({
            message: "Server Error: Unable to fetch enrollments",
            error: error.message,
            correlationId: getCorrelationId()
        });
    }
});

// Get a specific enrollment by ID
router.get("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        let id = req.params.id;
        let enrollments = await Enrollment.findById(id);
        if (!enrollments) {
            logger.warn(`Enrollment with ID ${id} not found`);
            return res.status(404).json({message: "Enrollment not found", correlationId: getCorrelationId()});
        }

        logger.info(`Fetched enrollment with ID: ${id}`);
        return res.status(200).json(enrollments);
    } catch (error) {
        logger.error(`Error fetching enrollment: ${error.message}`);
        res.status(500).json({
            message: "Server Error: Unable to fetch enrollment", error: error.message, correlationId: getCorrelationId()
        });
    }
});

// Get enrollment by student ID
router.get("/student/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR, ROLES.STUDENT]), restrictStudentToOwnData, async (req, res) => {
    try {
        let enrollments = await Enrollment.find({
            student: req.params.id,
        });

        if (!enrollments.length) {
            logger.warn(`No enrollments found for student with ID ${req.params.id}`);
            return res
                .status(404)
                .json({message: "No enrollments found for this student", correlationId: getCorrelationId()});
        }

        const courses = await fetchCourses();
        enrollments = enrollments.map((enrollment) => {
            const enrollmentObj = enrollment.toObject(); // Convert to plain object if it's a Mongoose document
            const course = courses.find((course) => course._id.toString() === enrollmentObj.course.toString());
            if (course) {
                enrollmentObj.course = course; // Replace course ID with the full course object
            }
            return enrollmentObj;
        });
        logger.info(`Fetched enrollments for student with ID: ${req.params.id}`);
        res.status(200).json(enrollments);
    } catch (error) {
        logger.error(`Error fetching enrollments for student: ${error.message}`);
        res.status(500).json({
            message: "Server Error: Unable to fetch enrollments for student",
            error: error.message,
            correlationId: getCorrelationId()
        });
    }
});

// Get enrollment by course ID
router.get("/course/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        const enrollments = await Enrollment.find({course: req.params.id})
        if (!enrollments.length) {
            logger.warn(`No enrollments found for course with ID ${req.params.id}`);
            return res.status(404).json({
                message: "No enrollments found for the course",
                correlationId: getCorrelationId()
            });
        }
        logger.info(`Fetched enrollments for course with ID: ${req.params.id}`);
        res.status(200).json(enrollments);
    } catch (error) {
        logger.error(`Error fetching enrollments for course: ${error.message}`);
        res.status(500).json({
            message: "Server Error: Unable to fetch enrollments for course",
            error: error.message,
            correlationId: getCorrelationId()
        });
    }
});

// Delete an enrollment by ID
router.delete("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        const enrollment = await Enrollment.findByIdAndDelete(req.params.id);

        if (!enrollment) {
            logger.warn(`Enrollment with ID ${req.params.id} not found for deletion`);
            return res.status(404).json({message: "Enrollment not found", correlationId: getCorrelationId()});
        }

        logger.info(`Enrollment with ID ${req.params.id} deleted successfully`);
        res
            .status(200)
            .json({message: "Enrollment deleted successfully", enrollment});
    } catch (error) {
        if (error.kind === "ObjectId") {
            logger.warn(`Invalid enrollment ID format: ${req.params.id}`);
            return res
                .status(400)
                .json({message: "Invalid enrollment ID format", correlationId: getCorrelationId()});
        }
        logger.error(`Error deleting enrollment: ${error.message}`);
        res.status(500).json({
            message: "Server Error: Unable to delete enrollment",
            error: error.message,
            correlationId: getCorrelationId()
        });
    }
});

module.exports = router;
