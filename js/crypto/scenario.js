const EC = require("elliptic").ec;
const crypto = require("crypto");
const ec = new EC("secp256k1");

const getEntropy = (pin) => {
  const result = crypto.createHash("sha256").update(pin).digest("hex");
  return result;
};

class Actor {
  constructor(name = "Alice") {
    this.name = name;
  }
  getName() {
    return this.name;
  }
}

class Server extends Actor {
  constructor(name = "Server") {
    super(name);
    this.publicKeys = {};
    console.log("Create server");
  }
  GenerateChallenge() {
    console.log("Generate challenge");
    return "challenge";
  }
  SavePublicKey(clientName, publicKey) {
    console.log("Save public key of " + clientName);
    this.publicKeys[clientName] = publicKey;
  }
  GetPublicKey(clientName) {
    console.log("Get public key of " + clientName);
    return this.publicKeys[clientName];
  }
  VerifySignature(clientName, signature, challenge) {
    const publicKey = this.GetPublicKey(clientName);
    const key = ec.keyFromPublic(publicKey, "hex");
    const result = key.verify(challenge, signature);
    return result;
  }
}

class Client extends Actor {
  constructor(name = "Client") {
    super(name);
  }
  CreateAsymmetricKeyPair(pin) {
    console.log("[step1] Create asymmetric key pair using pin: " + pin);
    const entropy = this.getEntropy(pin);
    const key = ec.genKeyPair({
      entropy: entropy,
      entropyEnc: "utf8",
    });
    this.saveKeyPair(key);
    return {
      privateKey: this.publicKey,
      publicKey: this.privateKey,
    };
  }

  SendPublicKey(server) {
    console.log("Send public key to server");
    server.SavePublicKey(this.name, this.publicKey);
  }
  SignChallenge(challenge) {
    console.log("Sign challenge");
    const key = ec.keyFromPrivate(this.privateKey, "hex");
    const signature = key.sign(challenge);
    return signature.toDER();
  }

  saveKeyPair(key) {
    this.keyPair = key;
    this.publicKey = key.getPublic("hex");
    this.privateKey = key.getPrivate("hex");
  }
  getEntropy(input) {
    const result = crypto.createHash("sha256").update(input).digest("hex");
    return result;
  }
}

function main() {
  const server = new Server();
  const client = new Client();
  // 1. create asymmetric key
  const pin = "123456";
  client.CreateAsymmetricKeyPair("123456");

  // 2. generate challenge
  const challenge = server.GenerateChallenge();

  // 3. send public key to server
  client.SendPublicKey(server);

  // 4. encrypt challenge with private key
  const signature = client.SignChallenge(challenge);

  // 5. decrypt challenge with public key
  const result = server.VerifySignature(client.getName(), signature, challenge);
  console.log(`Verify result: ${result}`);
}

main();
