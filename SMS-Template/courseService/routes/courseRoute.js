const express = require("express");
const Course = require("../models/course");
const router = express.Router();
const { verifyRole } = require("./auth/util");
const { ROLES } = require("../../consts");
// Create a new course

router.post("/", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {        
  try {
    req.body.createdBy = req.user.id; // Set course creator
    const course = new Course(req.body);
    await course.save();
    res.status(201).json(course);
  } catch (error) {
    res.status(400).json({ error: error.message });
   
  }
});
 
// Get all courses
router.get("/", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR, ROLES.ENROLLMENT_SERVICE]), async (req, res) => {
  try {
    let courses;
 
    if (req.user.role === ROLES.PROFESSOR) {
      courses = await Course.find({ createdBy: req.user.id }); // Only their own
    } else {
      courses = await Course.find(); // Admins and enrollment service see all
                           
    }
 
    res.status(200).json(courses);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
 
 
// Get a single course by ID
router.get("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR, ROLES.ENROLLMENT_SERVICE]), async (req, res) => {
             
  try {
    const course = await Course.findById(req.params.id);
 
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }
 
    if (req.user.role === ROLES.PROFESSOR && course.createdBy.toString() !== req.user.id) {
      return res.status(403).json({ message: "Access denied to this course" });
    }
 
    res.status(200).json(course);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
 
// Update a course by ID
router.put("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
             
  try {  
    const course = await Course.findById(req.params.id);    
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }
 
    if (req.user.role === ROLES.PROFESSOR && course.createdBy.toString() !== req.user.id) {
      return res.status(403).json({ message: "You cannot edit this course" });
    }
    // Remove the `createdBy` field from the request body
    if ("createdBy" in req.body) {
      delete req.body.createdBy;
    }
    const updatedCourse = await Course.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    });
 
    res.status(200).json(updatedCourse);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
 
 
// DELETE a course by ID
router.delete("/:id", verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
             
  try {
    const course = await Course.findById(req.params.id); //Extract the course ID from the route parameter
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }
 
    if (req.user.role === ROLES.PROFESSOR && course.createdBy.toString() !== req.user.id) {
      return res.status(403).json({ message: "You cannot delete this course" });
    }
    // Attempt to find and delete the course
    await course.deleteOne();
    // Respond with success message
    res.status(200).json({ message: "Course deleted successfully", course });
  } catch (error) {
    // Handle invalid ObjectId format
    if (error.kind === "ObjectId") {
      return res.status(400).json({ message: "Invalid course ID format" });
    }
    // Handle other server errors        
    res.status(500).json({ message: "Server Error: Unable to delete course" });
   
  }
});
 
 
module.exports = router;
 
 