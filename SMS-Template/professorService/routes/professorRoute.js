const express = require("express");
const Professor = require("../models/professor");
const { verifyRole, restrictProfessorToOwnData} = require("./auth/util");
const { ROLES } = require("../../consts");

const router = express.Router();

// Create a new professor
router.post("/",verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    // Ensure all fields are provided
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // Check for duplicate email or phone
    const existingProfessor = await Professor.findOne({
      $or: [{ email }, { phone }],
    });
    if (existingProfessor) {
      return res.status(409).json({ message: "Email or phone already exists" });
    }

    // Create and save the professor
    const professor = new Professor({ name, email, phone, password });
    await professor.save();

    res
      .status(201)
      .json({ message: "Professor created successfully", professor });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error", error: error.message });
  }
});

// Get all professors
router.get("/",verifyRole([ROLES.ADMIN, ROLES.AUTH_SERVICE, ROLES.ENROLLMENT_SERVICE]), async (req, res) => {
  try {
    if (
        req.user.id === ROLES.AUTH_SERVICE &&
        req.user.roles.includes(ROLES.AUTH_SERVICE)
    ) {
      const professors = await Professor.find();
      return res.status(200).json(professors);
    }
    const professors = await Professor.find().select("-password"); // Exclude password
    return res.status(200).json(professors);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error", error: error.message });
  }
});

// Get a specific professor by ID
router.get("/:id",verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), restrictProfessorToOwnData, async (req, res) => {
  try {
    const professor = await Professor.findById(req.params.id).select(
      "-password"
    );

    if (!professor) {
      return res.status(404).json({ message: "Professor not found" });
    }

    res.status(200).json(professor);
  } catch (error) {
    console.error(error);
    if (error.kind === "ObjectId") {
      return res.status(400).json({ message: "Invalid professor ID format" });
    }
    res.status(500).json({ message: "Server Error", error: error.message });
  }
});

// Update a professor
router.put("/:id",verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), restrictProfessorToOwnData, async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    const updatedData = { name, email, phone };
    if (password) {
      const salt = await bcrypt.genSalt(10);
      updatedData.password = await bcrypt.hash(password, salt);
    }

    const professor = await Professor.findByIdAndUpdate(
      req.params.id,
      updatedData,
      {
        new: true,
      }
    );

    if (!professor) {
      return res.status(404).json({ message: "Professor not found" });
    }

    res
      .status(200)
      .json({ message: "Professor updated successfully", professor });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error", error: error.message });
  }
});

// Delete a professor
router.delete("/:id",verifyRole([ROLES.ADMIN, ROLES.PROFESSOR]), restrictProfessorToOwnData, async (req, res) => {
  try {
    const professor = await Professor.findByIdAndDelete(req.params.id);

    if (!professor) {
      return res.status(404).json({ message: "Professor not found" });
    }

    res
      .status(200)
      .json({ message: "Professor deleted successfully", professor });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server Error", error: error.message });
  }
});

module.exports = router;
