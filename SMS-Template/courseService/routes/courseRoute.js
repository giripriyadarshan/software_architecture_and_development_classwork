const express = require("express");
const Course = require("../models/course");
const router = express.Router();
const { verifyRole } = require("./auth/util");
const { ROLES } = require("../../consts");
// Create a new course
router.post(
    "/",
    verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]),
    async (req, res) => {
      try {
        if (!req.user || !req.user.userId) {
          console.error("User ID (userId) not found in token payload for createdBy field.");
          return res.status(401).json({ error: "Unauthorized: User ID missing from token." });
        }

        const courseData = { ...req.body };
        courseData.createdBy = req.user.userId;

        const course = new Course(courseData);
        await course.save();
        res.status(201).json(course);
      } catch (error) {
        console.error("Error creating course:", error);
        res.status(400).json({ error: error.message });
      }
    }
);

// Get all courses
router.get(
    "/",
    verifyRole([ROLES.ADMIN, ROLES.PROFESSOR, ROLES.ENROLLMENT_SERVICE]),
    async (req, res) => {
      try {
        const courses = await Course.find();
        res.status(200).json(courses);
      } catch (error) {
        console.error("Error fetching all courses:", error);
        res.status(500).json({ error: error.message });
      }
    }
);

// Get a single course by ID
router.get(
    "/:id",
    verifyRole([ROLES.ADMIN, ROLES.PROFESSOR, ROLES.ENROLLMENT_SERVICE]),
    async (req, res) => {
      try {
        const course = await Course.findById(req.params.id);
        if (!course) {
          return res.status(404).json({ message: "Course not found" });
        }
        res.status(200).json(course);
      } catch (error) {
        console.error(`Error fetching course ${req.params.id}:`, error);
        res.status(500).json({ error: error.message });
      }
    }
);

// Update a course by ID
router.put(
    "/:id",
    verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]),
    async (req, res) => {
      try {
        const course = await Course.findById(req.params.id);
        if (!course) {
          return res.status(404).json({ message: "Course not found" });
        }

        if (!req.user || !req.user.userId) {
          console.error("User ID (userId) not found in token payload for ownership check.");
          return res.status(401).json({ error: "Unauthorized: User ID missing from token for ownership check." });
        }

        if (
            (req.user.roles && req.user.roles.includes(ROLES.ADMIN)) || // Check if roles array exists and includes ADMIN
            course.createdBy === req.user.userId
        ) {
          // Prevent createdBy from being updated
          if ("createdBy" in req.body) {
            delete req.body.createdBy;
          }

          const updatedCourse = await Course.findByIdAndUpdate(
              req.params.id,
              req.body,
              {
                new: true,
                runValidators: true,
              }
          );
          res.status(200).json(updatedCourse);
        } else {
          return res.status(403).json({
            message: "Access forbidden: You can only update courses you created.",
          });
        }
      } catch (error) {
        console.error(`Error updating course ${req.params.id}:`, error);
        res.status(400).json({ error: error.message });
      }
    }
);

// DELETE a course by ID
router.delete(
    "/:id",
    verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]),
    async (req, res) => {
      try {
        const courseId = req.params.id;
        const course = await Course.findById(courseId);

        if (!course) {
          return res.status(404).json({ message: "Course not found" });
        }

        // Ensure req.user and req.user.userId exist for ownership check
        if (!req.user || !req.user.userId) {
          console.error("User ID (userId) not found in token payload for ownership check.");
          return res.status(401).json({ error: "Unauthorized: User ID missing from token for ownership check." });
        }

        // Ownership Check: Allow if user is ADMIN or the creator of the course
        // Ensure to compare with req.user.userId as createdBy stores userId
        if ((req.user.roles && req.user.roles.includes(ROLES.ADMIN)) || course.createdBy === req.user.userId ) {
          await Course.findByIdAndDelete(courseId);
          res
              .status(200)
              .json({ message: "Course deleted successfully", course });
        } else {
          return res.status(403).json({
            message: "Access forbidden: You can only delete courses you created.",
          });
        }
      } catch (error) {
        console.error(`Error deleting course ${req.params.id}:`, error);
        res.status(500).json({ error: error.message });
      }
    }
);

module.exports = router;