const express = require("express");
const Course = require("../models/course");
const router = express.Router();
const {verifyRole, jwtRateLimiter} = require("./auth/util");
const {ROLES} = require("../../consts");
const {studentServiceLogger: logger} = require("../../logging");
const {getCorrelationId} = require("../../correlationId");

// Create a new course
router.post("/", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        if (!req.user || !req.user.userId) {
            logger.warn("User ID (userId) not found in token payload.");
            return res.status(401).json({
                error: "Unauthorized: User ID missing from token.", correlationId: getCorrelationId()
            });
        }

        const courseData = {...req.body};
        courseData.createdBy = req.user.userId;

        const course = new Course(courseData);
        await course.save();
        logger.info(`New course created with ID: ${course._id} by user: ${req.user.userId}`);
        res.status(201).json(course);
    } catch (error) {
        logger.error(`Error creating course: ${error.message}`);
        res.status(400).json({error: error.message, correlationId: getCorrelationId()});
    }
});

// Get all courses
router.get("/", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR, ROLES.ENROLLMENT_SERVICE]), jwtRateLimiter, async (req, res) => {
    try {
        const courses = await Course.find();
        logger.info(`Fetched all courses successfully`);
        res.status(200).json(courses);
    } catch (error) {
        logger.error(`Error fetching courses: ${error.message}`);
        res.status(500).json({error: error.message, correlationId: getCorrelationId()});
    }
});

// Get a single course by ID
router.get("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR, ROLES.ENROLLMENT_SERVICE]), async (req, res) => {
    try {
        const course = await Course.findById(req.params.id);
        if (!course) {
            logger.warn(`Course with ID ${req.params.id} not found`);
            return res.status(404).json({message: "Course not found", correlationId: getCorrelationId()});
        }
        logger.info(`Fetched course with ID: ${req.params.id}`);
        res.status(200).json(course);
    } catch (error) {
        logger.error(`Error fetching course with ID ${req.params.id}: ${error.message}`);
        res.status(500).json({error: error.message, correlationId: getCorrelationId()});
    }
});

// Update a course by ID
router.put("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        const course = await Course.findById(req.params.id);
        if (!course) {
            logger.warn(`Course with ID ${req.params.id} not found for update`);
            return res.status(404).json({message: "Course not found", correlationId: getCorrelationId()});
        }

        if (!req.user || !req.user.userId) {
            logger.warn("User ID (userId) not found in token payload for ownership check.");
            return res.status(401).json({
                error: "Unauthorized: User ID missing from token for ownership check.",
                correlationId: getCorrelationId()
            });
        }

        if ((req.user.roles && req.user.roles.includes(ROLES.ADMIN)) || // Check if roles array exists and includes ADMIN
            course.createdBy === req.user.userId) {
            // Prevent createdBy from being updated
            if ("createdBy" in req.body) {
                delete req.body.createdBy;
            }

            const updatedCourse = await Course.findByIdAndUpdate(req.params.id, req.body, {
                new: true, runValidators: true,
            });
            logger.info(`Course with ID ${req.params.id} updated successfully by user: ${req.user.userId}`);
            res.status(200).json(updatedCourse);
        } else {
            logger.warn(`Access forbidden: User with ID ${req.user.userId} tried to update course ${req.params.id} they did not create.`);
            return res.status(403).json({
                message: "Access forbidden: You can only update courses you created.",
                correlationId: getCorrelationId()
            });
        }
    } catch (error) {
        logger.error(`Error updating course ${req.params.id}: ${error.message}`);
        res.status(400).json({error: error.message, correlationId: getCorrelationId()});
    }
});

// DELETE a course by ID
router.delete("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        const courseId = req.params.id;
        const course = await Course.findById(courseId);

        if (!course) {
            logger.warn(`Course with ID ${courseId} not found for deletion`);
            return res.status(404).json({message: "Course not found", correlationId: getCorrelationId()});
        }

        // Ensure req.user and req.user.userId exist for ownership check
        if (!req.user || !req.user.userId) {
            logger.warn("User ID (userId) not found in token payload for ownership check.");
            return res.status(401).json({
                error: "Unauthorized: User ID missing from token for ownership check.",
                correlationId: getCorrelationId()
            });
        }

        // Ownership Check: Allow if user is ADMIN or the creator of the course
        // Ensure to compare with req.user.userId as createdBy stores userId
        if ((req.user.roles && req.user.roles.includes(ROLES.ADMIN)) || course.createdBy === req.user.userId) {
            await Course.findByIdAndDelete(courseId);
            logger.info(`Course with ID ${courseId} deleted successfully by user: ${req.user.userId}`);
            res
                .status(200)
                .json({message: "Course deleted successfully", course});
        } else {
            logger.warn(`Access forbidden: User with ID ${req.user.userId} tried to delete course ${courseId} they did not create.`);
            return res.status(403).json({
                message: "Access forbidden: You can only delete courses you created.",
                correlationId: getCorrelationId()
            });
        }
    } catch (error) {
        logger.error(`Error deleting course ${req.params.id}: ${error.message}`);
        res.status(500).json({error: error.message, correlationId: getCorrelationId()});
    }
});

module.exports = router;