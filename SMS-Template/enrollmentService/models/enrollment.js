const mongoose = require("mongoose");

// Define the Enrollment Schema
const enrollmentSchema = new mongoose.Schema({
    student: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
    },
    course: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
    },
    enrollment: {
        type: Date,
        default: Date.now,
    }
});

enrollmentSchema.index({student: 1, course: 1}, {unique: true});

const Enrollment = mongoose.model("Enrollment", enrollmentSchema);

module.exports = Enrollment;
