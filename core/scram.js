/** @fileOverview SCRAM implementation using SJCL functions.
 *
 * @author Konk
 */

/** SCRAM
 *
 * Generate SCRAM responses for a given password, salt, authMessage, iteration count, and hash function.
 *
 * @param {bitArray|String} password  The password.
 * @param {bitArray|String} salt The salt.
 * @param {bitArray|String} authMessage The SCRAM auth message.
 * @param {Number} [iterations=1000] The number of iterations.  Higher numbers make the function slower but more secure.
 * @param {Object} [hash] The SJCL hash function to be used when calculating the SCRAM response.
 *
 * @return {bitArray} the derived key.
 */
sjcl.misc.scram = function (password, salt, authMessage, iterations, hash) {
  var clientKeyHMACMessage = "Client Key";
  var serverKeyHMACMessage = "Server Key";
  var clientKey, serverKey, clientSignature, serverSignature;
  var clientProof = [];

  iterations = iterations || 1000;

  if (keyLength < 0 || iterations < 0) {
    throw sjcl.exception.invalid("invalid params to scram");
  }

  var str2bin = function (str) {
    var bin = [];
    var mask = 255;

    for (var i = 0; i < str.length * 8; i += 8) {
      bin[i>>5] |= (str.charCodeAt(i / 8) & mask) << (24 - i % 32);
    }

    return bin;
  };

  var bin2str = function (bin) {
    var str = "";
    var mask = 255;

    for (var i = 0; i < bin.length * 32; i += 8) {
      str += String.fromCharCode((bin[i>>5] >>> (24 - i%32)) & mask);
    }

    return str;
  };

  var bin2b64 = function (bin) {
    return Base64.encode(bin2str(bin));
  };

  if (typeof password === "string") {
    password = str2bin(password);
  }

  if (typeof salt === "string") {
    salt = str2bin(salt);
  }

  if (typeof authMessage === "string") {
    //authMessage = sjcl.codec.utf8String.toBits(authMessage);
    authMessage = str2bin(authMessage);
  }

  var hmac = new sjcl.misc.hmac(password, hash);

  var u, ui, i, j, k, b = sjcl.bitArray;

  u = ui = hmac.encrypt(salt);

  for (i = 0; i < iterations - 1; i++) {
    ui = hmac.encrypt(ui);

    for (j = 0; j < ui.length; j++) {
      u[j] ^= ui[j];
    }
  }

  var saltedPassword = u;

  clientKey = new sjcl.misc.hmac(saltedPassword, hash).encrypt(clientKeyHMACMessage);
  serverKey = new sjcl.misc.hmac(saltedPassword, hash).encrypt(serverKeyHMACMessage);

  clientSignature = new sjcl.misc.hmac(hash.hash(clientKey), hash).encrypt(authMessage);
  serverSignature = new sjcl.misc.hmac(serverKey, hash).encrypt(authMessage);

  for (k = 0; k < 5; k++) {
    clientProof[k] = clientKey[k] ^ clientSignature[k];
  }

  return {
    clientSignature: bin2b64(clientSignature),
    serverSignature: bin2b64(serverSignature),
    clientKey: bin2b64(clientKey),
    serverKey: bin2b64(serverKey),
    clientProof: bin2b64(clientProof)
  }
};
