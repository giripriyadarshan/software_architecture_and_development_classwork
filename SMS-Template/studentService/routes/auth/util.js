const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const axios = require("axios");
const {ROLES} = require("../../../consts");
const rateLimit = require("express-rate-limit");
const {studentServiceLogger: logger} = require("../../logging");
const {getCorrelationId} = require("../../correlationId");

dotenv.config();

async function fetchJWKS(jku) {
    const response = await axios.get(jku);
    return response.data.keys;
}

function getPublicKeyFromJWKS(kid, keys) {
    const key = keys.find((k) => k.kid === kid);

    if (!key) {
        logger.error(`No matching key found for kid: ${kid}`);
        throw new Error("Unable to find a signing key that matches the 'kid'");
    }

    return `-----BEGIN PUBLIC KEY-----\n${key.n}\n-----END PUBLIC KEY-----`;
}

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
        const token = req.headers.authorization && req.headers.authorization.split(" ")[1];

        if (!token) {
            logger.warn("Authorization token is missing");
            return res
                .status(401)
                .json({
                    message: "Authorization token is missing", correlationId: getCorrelationId()
                });
        }

        try {
            req.user = await verifyJWTWithJWKS(token);

            let userRoles = [];
            if (Array.isArray(req.user.role)) {
                userRoles = req.user.role;
            } else if (typeof req.user.role === 'string') {
                userRoles = [req.user.role];
            }
            const hasRequiredRole = userRoles.some((role) => requiredRoles.includes(role));
            if (hasRequiredRole) {
                return next();
            } else {
                logger.warn(`Access forbidden: User with roles ${userRoles.join(", ")} does not have required roles ${requiredRoles.join(", ")}`);
                return res
                    .status(403)
                    .json({
                        message: "Access forbidden: Insufficient role", correlationId: getCorrelationId()
                    });
            }
        } catch (error) {
            logger.error(`JWT verification failed: ${error.message}`);
            return res
                .status(403)
                .json({message: "Invalid or expired token", error: error.message}, {correlationId: getCorrelationId()});
        }
    };
}

function restrictStudentToOwnData(req, res, next) {

    let hasStudentRole = false;
    if (Array.isArray(req.user.role)) {
        hasStudentRole = req.user.role.includes(ROLES.STUDENT);
    } else if (typeof req.user.role === 'string') {
        hasStudentRole = req.user.role === ROLES.STUDENT;
    }
    if (hasStudentRole && req.user.id !== req.params.id) {
        logger.warn(`Access forbidden: Student with ID ${req.user.id} tried to access data of student with ID ${req.params.id}`);
        return res.status(403).json({
            message: "Access forbidden: You can only access your own data", correlationId: getCorrelationId()
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
        logger.warn(`Rate limit exceeded for user ID: ${req.user.id}`);
        res
            .status(429)
            .json({
                message: "You crossed the rate limit. Please try again later.", correlationId: getCorrelationId()
            });
    },
});

module.exports = {
    verifyRole, restrictStudentToOwnData, jwtRateLimiter,
};