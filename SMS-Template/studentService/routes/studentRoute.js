const express = require("express");

const Student = require("../models/student");

const { verifyRole, restrictStudentToOwnData } = require("./auth/util");
const { ROLES } = require("../../consts");

const router = express.Router();

// POST A NEW STUDENT
router.post("/", async (req,res) => {
    const { name,email,password } = req.body;

    if(!name || !email || !password) {
        return res.status(400).json({message:"Provide name, email and password"});
    }
    try{
        //check if student exists
        const existingStudent= await Student.findOne({email});
        if(existingStudent){
            return res.status(400).json({message:"Student already exists"});
        }
        const newStudent= new Student({name,email,password});
        const savedStudent= await newStudent.save();

        return res.status(201).json(savedStudent);                // post request
    }   catch (error) {
         return res.status(500).json({message:"Unable to create student"});

    }
});
    //get request for posting students
    router.get("/", async (req, res) => {
    try {
        const students = await Student.find();
        return res.status(200).json(students);
    } catch (error) {
        return res.status(500).json({ message: "Unable to Find students" });
    }
    });

    // GET - Get one student by email
    router.get("/:email", async (req, res) => {
    const {email} = req.params;
    try {
        const student = await Student.findOne({email});
        if (!student) {
            return res.status(404).json({ message: "Student not found" });
        }
        return res.status(200).json(student);
    } catch (error) {
        return res.status(500).json({ message: "Unable to find student" });
    }
});
 
// PUT/PATCH - Update student by email
    router.put("/:email", async (req, res) => {
    const { email } = req.params;
    const { name, password } = req.body;
 
    if (!name || !password) {
        return res.status(400).json({ message: "Provide name and password to update" });
    }
 
    try {
        const updatedStudent = await Student.findOneAndUpdate(
            { email },
            { name, email, password },
            { new: true, runValidators: true }
        );
        if (!updatedStudent) {
            return res.status(404).json({ message: "Student not found" });
        }
        return res.status(200).json(updatedStudent);
    } catch (error) {
        return res.status(500).json({ message: "Unable to update student" });
    }
});
 
// PATCH - update particular field/Partial Update
    router.patch("/:email", async (req, res) => {
    const { email } = req.params;
    try {
        const updatedStudent = await Student.findOneAndUpdate(
            { email },
            { $set: req.body },
            { new: true, runValidators: true }
        );
        if (!updatedStudent) {
            return res.status(404).json({ message: "Student not found" });
        }
        return res.status(200).json(updatedStudent);
    } catch (error) {
        return res.status(500).json({ message: "Unable to update student" });
    }
});
 
 
// DELETE - Remove student by email
    router.delete("/:email", async (req, res) => {
    const { email } = req.params;
    try {
        const deletedStudent = await Student.findOneAndDelete({ email });
        if (!deletedStudent) {
            return res.status(404).json({ message: "Student not found" });
        }
        return res.status(200).json({ message: "Student deleted successfully" });
    } catch (error) {
        return res.status(500).json({ message: "Error deleting student" });
    }
});


module.exports = router;
