const fs = require("fs");
const jwt = require("jsonwebtoken");
const path = require("path");
const dotenv = require("dotenv");
const axios = require("axios");
const {
    STUDENT_SERVICE, PROFESSOR__SERVICE, ROLES,
} = require("../../../consts");
const {authServiceLogger: logger} = require("../../../logging");
const {getCorrelationId} = require("../../../correlationId");

dotenv.config();

const keysBasePath = path.join(__dirname, "keys");

const privateKey = fs.readFileSync(path.join(keysBasePath, "private.key"), "utf8");
const publicKey = fs.readFileSync(path.join(keysBasePath, "public.key"), "utf8");

const kid = "1";
const authServicePort = process.env.PORT || 5001;
const jku = `http://localhost:${authServicePort}/.well-known/jwks.json`;

// Generate a JWT using the private key
function generateJWTWithPrivateKey(payload) {
    try {
        const token = jwt.sign(payload, privateKey, {
            algorithm: "RS256", expiresIn: "1h", header: {
                kid: kid, jku: jku,
            },
        });
        return token;
    } catch (error) {
        logger.error("Error generating JWT:", error);
        throw new Error("Failed to generate JWT");
    }
}

// JWT verification function
function verifyJWTWithPublicKey(token) {
    try {
        return jwt.verify(token, publicKey, {algorithms: ["RS256"]});
    } catch (error) {
        logger.error("Error verifying JWT:", error);
        throw new Error("Invalid or expired token");
    }
}

async function fetchStudents() {
    let token = generateJWTWithPrivateKey({
        id: ROLES.AUTH_SERVICE, role: [ROLES.AUTH_SERVICE],
    });
    const response = await axios.get(`${STUDENT_SERVICE}`, {
        headers: {
            Authorization: `Bearer ${token}`,
        },
    });
    logger.info(`Fetched students from ${STUDENT_SERVICE} with token: ${token}`);
    return response.data;
}

async function fetchProfessors() {
    let token = generateJWTWithPrivateKey({
        id: ROLES.AUTH_SERVICE, role: [ROLES.AUTH_SERVICE],
    });
    const response = await axios.get(`${PROFESSOR__SERVICE}`, {
        headers: {
            Authorization: `Bearer ${token}`,
        },
    });
    logger.info(`Fetched professors from ${PROFESSOR__SERVICE} with token: ${token}`);
    return response.data;
}

module.exports = {
    kid, jku, generateJWTWithPrivateKey, verifyJWTWithPublicKey, fetchStudents, fetchProfessors,
};