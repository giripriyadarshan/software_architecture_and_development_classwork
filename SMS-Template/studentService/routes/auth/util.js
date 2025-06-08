const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const axios = require("axios");
const { ROLES } = require("../../../consts");

dotenv.config();

async function fetchJWKS(jku) {
  const response = await axios.get(jku);
  return response.data.keys;
}

function getPublicKeyFromJWKS(kid, keys) {
  const key = keys.find((k) => k.kid === kid);

  if (!key) {
    throw new Error("Unable to find a signing key that matches the 'kid'");
  }

  return `-----BEGIN PUBLIC KEY-----\n${key.n}\n-----END PUBLIC KEY-----`;
}

async function verifyJWTWithJWKS(token) {
  const decodedHeader = jwt.decode(token, { complete: true }).header;
  const { kid, alg, jku } = decodedHeader;

  if (!kid || !jku) {
    throw new Error("JWT header is missing 'kid' or 'jku'");
  }

  if (alg !== "RS256") {
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  const keys = await fetchJWKS(jku);
  const publicKey = getPublicKeyFromJWKS(kid, keys);

  return jwt.verify(token, publicKey, { algorithms: ["RS256"] });
}

// Role-based Access Control Middleware
function verifyRole(requiredRoles) {
  return async (req, res, next) => {
    const token =
        req.headers.authorization && req.headers.authorization.split(" ")[1];

    if (!token) {
      return res
          .status(401)
          .json({ message: "Authorization token is missing" });
    }

    try {
      req.user = await verifyJWTWithJWKS(token);

      const userRoles = req.user.roles || [];
      const hasRequiredRole = userRoles.some((role) =>
          requiredRoles.includes(role)
      );
      if (hasRequiredRole) {
        return next();
      } else {
        return res
            .status(403)
            .json({ message: "Access forbidden: Insufficient role" });
      }
    } catch (error) {
      console.error(error);
      return res
          .status(403)
          .json({ message: "Invalid or expired token", error: error.message });
    }
  };
}

function restrictStudentToOwnData(req, res, next) {
  if (req.user.roles.includes(ROLES.STUDENT) && req.user.id !== req.params.id) {
    return res.status(403).json({
      message: "Access forbidden: You can only access your own data",
    });
  }
  next();
}

module.exports = {
  verifyRole,
  restrictStudentToOwnData,
};