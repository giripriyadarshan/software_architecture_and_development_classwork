const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const axios = require("axios");
const fs = require("fs");
const path = require("path");
const rateLimit = require("express-rate-limit");

const {ROLES, STUDENT_SERVICE, COURSE_SERVICE} = require("../../../consts");
// const { getCorrelationId } = require("../../../correlationId");

dotenv.config();

const axiosInstance = axios.create();

// axiosInstance.interceptors.request.use(
//   (req) => {
//     const correlationId = getCorrelationId(); // Retrieve the correlation ID
//     req.headers["x-correlation-id"] = correlationId; // Add it to the headers
//     return req;
//   },
//   (error) => {
//     return Promise.reject(error);
//   }
// );
const kid = "1";
const jku = `http://localhost:${process.env.PORT}/.well-known/jwks.json`;

// Define additional headers
const customHeaders = {
    kid, // Replace with the actual Key ID
    jku, // Replace with your JWKS URL
};

// Path to your private and public keys
const privateKey = fs.readFileSync(
    path.join(__dirname, "../auth/keys/private.key"),
    "utf8"
);
const publicKey = fs.readFileSync(
    path.join(__dirname, "../auth/keys/public.key"),
    "utf8"
);

/**
 * Fetch the JWKS from a given URI.
 * @param {string} jku - The JWKS URI from the JWT header.
 * @returns {Promise<Array>} - A promise that resolves to the JWKS keys.
 */
async function fetchJWKS(jku) {
    const response = await axios.get(jku);
    return response.data.keys;
}

/**
 * Get the public key from JWKS.
 * @param {string} kid - The key ID from the JWT header.
 * @param {Array} keys - The JWKS keys.
 * @returns {string} - The corresponding public key in PEM format.
 */
function getPublicKeyFromJWKS(kid, keys) {
    const key = keys.find((k) => k.kid === kid);

    if (!key) {
        throw new Error("Unable to find a signing key that matches the 'kid'");
    }

    return `-----BEGIN PUBLIC KEY-----\n${key.n}\n-----END PUBLIC KEY-----`;
}

/**
 * Verify a JWT token using the JWKS URI in the `jku` header.
 * @param {string} token - The JWT token to verify.
 * @returns {Promise<object>} - A promise that resolves to the decoded JWT payload.
 */
async function verifyJWTWithJWKS(token) {
    const decodedHeader = jwt.decode(token, {complete: true}).header;
    const {kid, alg, jku} = decodedHeader;

    if (!kid || !jku) {
        throw new Error("JWT header is missing 'kid' or 'jku'");
    }

    if (alg !== "RS256") {
        throw new Error(`Unsupported algorithm: ${alg}`);
    }

    const keys = await fetchJWKS(jku);
    const publicKey = getPublicKeyFromJWKS(kid, keys);

    return jwt.verify(token, publicKey, {algorithms: ["RS256"]});
}

function generateJWTWithPrivateKey(payload) {
    // Sign the JWT using RS256 (asymmetric encryption)
    const token = jwt.sign(payload, privateKey, {
        algorithm: "RS256",
        header: customHeaders,
        expiresIn: "6h", // Set expiration
    });
    return token;
}

// Role-based Access Control Middleware
function verifyRole(requiredRoles) {
    return async (req, res, next) => {
        const token =
            req.headers.authorization && req.headers.authorization.split(" ")[1]; // Extract token from 'Bearer <token>'

        if (!token) {
            return res
                .status(401)
                .json({message: "Authorization token is missing"});
        }

        try {
            // Step 1: Verify the JWT token using JWKS
            req.user = await verifyJWTWithJWKS(token); // Attach the decoded payload (user data) to the request object

            // Step 2: Check if the user has any of the required roles
            let userRoles = [];
            if (Array.isArray(req.user.role)) {
                userRoles = req.user.role;
            } else if (typeof req.user.role === 'string') {
                userRoles = [req.user.role];
            }
            const hasRequiredRole = userRoles.some((role) =>
                requiredRoles.includes(role)
            );
            if (hasRequiredRole) {
                return next(); // User has at least one of the required roles, so proceed
            } else {
                return res
                    .status(403)
                    .json({message: "Access forbidden: Insufficient role"});
            }
        } catch (error) {
            console.error(error);
            return res
                .status(403)
                .json({message: "Invalid or expired token", error: error.message});
        }
    };
}

async function fetchStudents() {
    let token = generateJWTWithPrivateKey({
        id: ROLES.ENROLLMENT_SERVICE,
        role: [ROLES.ENROLLMENT_SERVICE],
    });
    const response = await axiosInstance.get(`${STUDENT_SERVICE}`, {
        headers: {
            Authorization: `Bearer ${token}`,
        },
    });
    return response.data;
}

async function fetchCourses() {
    let token = generateJWTWithPrivateKey({
        id: ROLES.ENROLLMENT_SERVICE,
        role: [ROLES.ENROLLMENT_SERVICE],
    });
    const response = await axiosInstance.get(`${COURSE_SERVICE}`, {
        headers: {
            Authorization: `Bearer ${token}`,
        },
    });
    return response.data;
}

function restrictStudentToOwnData(req, res, next) {
    let hasStudentRole = false;
    if (Array.isArray(req.user.role)) {
        hasStudentRole = req.user.role.includes(ROLES.STUDENT);
    } else if (typeof req.user.role === 'string') {
        hasStudentRole = req.user.role === ROLES.STUDENT;
    }
    if (hasStudentRole && req.user.id !== req.params.id) {
        return res.status(403).json({
            message: "Access forbidden: You can only access your own data",
        });
    }
    next();
}

const jwtRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: "You crossed the rate limit. Please try again later.",
    keyGenerator: (req) => req.user.id,
    handler: (req, res) => {
        res
            .status(429)
            .json({message: "You crossed the rate limit. Please try again later."});
    },
});

module.exports = {
    kid,
    verifyRole,
    restrictStudentToOwnData,
    fetchStudents,
    fetchCourses,
    jwtRateLimiter,
};
