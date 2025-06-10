const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const axios = require("axios");
const {ROLES} = require("../../../consts");
const rateLimit = require("express-rate-limit");
const {studentServiceLogger: logger} = require("../../../logging");
const {getCorrelationId} = require("../../../correlationId");

dotenv.config();

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
        logger.error(`No matching key found for kid: ${kid}`);
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
        logger.error("JWT header is missing 'kid' or 'jku'");
        throw new Error("JWT header is missing 'kid' or 'jku'");
    }

    if (alg !== "RS256") {
        logger.error(`Unsupported algorithm: ${alg}`);
        throw new Error(`Unsupported algorithm: ${alg}`);
    }

    const keys = await fetchJWKS(jku);
    const publicKey = getPublicKeyFromJWKS(kid, keys);

    return jwt.verify(token, publicKey, {algorithms: ["RS256"]});
}

// Role-based Access Control Middleware
function verifyRole(requiredRoles) {
    return async (req, res, next) => {
        const token = req.headers.authorization && req.headers.authorization.split(" ")[1]; // Extract token from 'Bearer <token>'

        if (!token) {
            logger.warn("Authorization token is missing");
            return res
                .status(401)
                .json({message: "Authorization token is missing", correlationId: getCorrelationId()});
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
            const hasRequiredRole = userRoles.some((role) => requiredRoles.includes(role));
            if (hasRequiredRole) {
                return next(); // User has at least one of the required roles, so proceed
            } else {
                logger.warn(`Access forbidden: User with roles ${userRoles.join(", ")} does not have required roles ${requiredRoles.join(", ")}`);
                return res
                    .status(403)
                    .json({message: "Access forbidden: Insufficient role", correlationId: getCorrelationId()});
            }
        } catch (error) {
            logger.error(`JWT verification failed: ${error.message}`);
            return res
                .status(403)
                .json({message: "Invalid or expired token", error: error.message, correlationId: getCorrelationId()});
        }
    };
}

function restrictProfessorToOwnData(req, res, next) {
    let hasProfessorRole = false;
    if (Array.isArray(req.user.role)) {
        hasProfessorRole = req.user.role.includes(ROLES.PROFESSOR);
    } else if (typeof req.user.role === 'string') {
        hasProfessorRole = req.user.role === ROLES.PROFESSOR;
    }
    if (hasProfessorRole && req.user.id !== req.params.id) {
        logger.warn(`Access forbidden: Professor with ID ${req.user.id} tried to access data of another professor with ID ${req.params.id}`);
        return res.status(403).json({
            message: "Access forbidden: You can only access your own data",
            correlationId: getCorrelationId()
        });
    }
    logger.info(`Professor with ID ${req.user.id} is accessing their own data`);
    next();
}

const jwtRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: "You crossed the rate limit. Please try again later.",
    keyGenerator: (req) => req.user.id,
    handler: (req, res) => {
        logger.warn(`Rate limit exceeded for user ID: ${req.user.id}`);
        res
            .status(429)
            .json({message: "You crossed the rate limit. Please try again later.", correlationId: getCorrelationId()});
    },
});

module.exports = {
    verifyRole, restrictProfessorToOwnData, jwtRateLimiter,
};
