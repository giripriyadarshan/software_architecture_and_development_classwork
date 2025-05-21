const express = require("express");

const Student = require("../models/student");

const { verifyRole, restrictStudentToOwnData } = require("./auth/util");
const { ROLES } = require("../../consts");

const router = express.Router();

// POST a new student
router.post("/", async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ message: "Please fill all fields" });
    }
    // check if the student already exists
    try {
        const studentExists = await Student.findOne({ email });
        if (studentExists) {
            return res.status(400).json({ message: "Student already exists" });

        }

        const newStudent = new Student({
            name,
            email,
            password,
        });

        const savedStudent = await newStudent.save();
        return res.status(201).json(savedStudent);
    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }

});

// GET all students
router.get("/", async (req, res) => {
    try {
        const students = await Student.find();
        return res.status(200).json(students);
    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

// GET a student by email
router.get("/:email", async (req, res) => {
    const { email } = req.params;
    try {
        const student = await Student.findOne({ email });
        if (!student) {
            return res.status(404).json({ message: "Student not found" });
        }
        return res.status(200).json(student);
    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

// PUT update a student by email
router.put("/:email", async (req, res) => {
    const { email } = req.params;
    const { name, password } = req.body;
    try {
        const student = await Student.findOne({ email });
        if (!student) {
            return res.status(404).json({ message: "Student not found" });
        }
        if (name) {
            student.name = name;
        }
        if (password) {
            student.password = password;
        }
        const updatedStudent = await student.save();
        return res.status(200).json(updatedStudent);
    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});

// DELETE a student by email
router.delete("/:email", async (req, res) => {
    const { email } = req.params;
    try {
        const student = await Student.findOneAndDelete({ email });
        if (!student) {
            return res.status(404).json({ message: "Student not found" });
        }
        return res.status(200).json({ message: "Student deleted" });
    } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
});



module.exports = router;
