const EC = require("elliptic").ec;
const crypto = require("crypto");

const ec = new EC("secp256k1");

const getEntropy = (pin) => {
  const result = crypto.createHash("sha256").update(pin).digest("hex");
  return result;
};

// 1. create asymmetric key
function createAsymmetricKey(pin = "123456") {
  const entropy = getEntropy(pin);
  const key = ec.genKeyPair({
    entropy: entropy,
    entropyEnc: "utf8",
  });
  return {
    privateKey: key.getPrivate("hex"),
    publicKey: key.getPublic("hex"),
  };
}
// 2. encrypt challenge with private key
function encryptChallenge(challenge, privateKey) {
  const key = ec.keyFromPrivate(privateKey, "hex");
  const signature = key.sign(challenge);
  return signature.toDER();
}

// 3. decrypt challenge with public key
function decryptChallenge(signature, challenge, publicKey) {
  const key = ec.keyFromPublic(publicKey, "hex");
  return key.verify(challenge, signature);
}

function main() {
  const keyPair = createAsymmetricKey();
  console.log("keyPair:", keyPair);
  const challenge = "challenge";
  const signature = encryptChallenge(challenge, keyPair.privateKey);
  console.log("signature:", signature);
  const isVerified = decryptChallenge(signature, challenge, keyPair.publicKey);
  console.log("isVerified:", isVerified);
}

main();
