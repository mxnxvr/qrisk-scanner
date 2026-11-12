// DELIBERATELY INSECURE sample code for the QRisk lab. Do not copy.
const crypto = require("crypto");
const https = require("https");
const { ml_kem768 } = require("@noble/post-quantum/ml-kem");

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 3072 });
const ecdh = crypto.createECDH("prime256v1");

function sessionId(user) {
  return crypto.createHash("sha1").update(user).digest("hex"); // critical
}

function seal(key, iv, data) {
  return crypto.createCipheriv("aes-256-gcm", key, iv).update(data); // quantum-safe
}

const insecureAgent = new https.Agent({ rejectUnauthorized: false }); // critical

const pqKeys = ml_kem768.keygen(); // post-quantum

module.exports = { sessionId, seal, insecureAgent, pqKeys, publicKey, privateKey, ecdh };
