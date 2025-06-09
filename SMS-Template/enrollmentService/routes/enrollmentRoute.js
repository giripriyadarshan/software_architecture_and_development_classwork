const express = require("express");

const Enrollment = require("../models/enrollment");

const router = express.Router();

const {
    verifyRole, restrictStudentToOwnData, fetchStudents, fetchCourses, jwtRateLimiter
} = require("./auth/util");
const {ROLES} = require("../../consts");

// Create a new enrollment
router.post("/", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        const {student, course} = req.body;

        // Ensure both student and course IDs are provided
        if (!student || !course) {
            return res
                .status(400)
                .json({message: "Student and Course are required"});
        }
        const students = fetchStudents();
        const existingStudent = students.find(s => s._id === student);
        if (!existingStudent) {
            return res.status(404).json({message: "Student does not exist"});
        }

        const courses = await fetchCourses();
        const existingCourse = courses.find(s => s._id === course);
        if (!existingCourse) {
            return res.status(404).json({message: "Course does not exist"});
        }

        const enrollment = new Enrollment({student, course});
        await enrollment.save();

        return res.status(200).json(enrollment);
    } catch (error) {
        console.log(error);

        res.status(500).json({
            message: "Server Error: Unable to create enrollment",
        });
    }
});
// Get all enrollments
router.get("/", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), jwtRateLimiter, async (req, res) => {
    try {
        let enrollments = await Enrollment.find();
        res.status(200).json(enrollments);
    } catch (error) {
        res.status(500).json({
            message: "Server Error: Unable to fetch enrollments",
        });
    }
});

// Get a specific enrollment by ID
router.get("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        let id = req.params.id;
        let enrollments = await Enrollment.findById({id});
        if (!enrollments) {
            return res.status(404).json({message: "Enrollment not found"});
        }

        return res.status(200).json(enrollments);
    } catch (error) {
        res.status(500).json({
            message: "Server Error: Unable to fetch enrollment",
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
            return res
                .status(404)
                .json({message: "No enrollments found for this student"});
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

        res.status(200).json(enrollments);
    } catch (error) {
        res.status(500).json({
            message: "Server Error: Unable to fetch enrollments for student",
        });
    }
});

// Get enrollment by course ID
router.get("/course/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        const enrollments = await Enrollment.find({course: req.params.id})
        if (!enrollments.length) {
            return res.status(404).json({message: "No enrollments found for the course"});
        }
        res.status(200).json(enrollments);
    } catch (error) {
        res.status(500).json({
            message: "Server Error: Unable to fetch enrollments for course",
        });
    }
});

// Delete an enrollment by ID
router.delete("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
    try {
        const enrollment = await Enrollment.findByIdAndDelete(req.params.id);

        if (!enrollment) {
            return res.status(404).json({message: "Enrollment not found"});
        }

        res
            .status(200)
            .json({message: "Enrollment deleted successfully", enrollment});
    } catch (error) {
        if (error.kind === "ObjectId") {
            return res
                .status(400)
                .json({message: "Invalid enrollment ID format"});
        }
        res.status(500).json({
            message: "Server Error: Unable to delete enrollment",
        });
    }
});

module.exports = router;
