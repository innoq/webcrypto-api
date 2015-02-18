// Password Based Key Derivation Web Cryptography API Example Code Snippet
// (see http://www.w3.org/TR/WebCryptoAPI/)
//
// The code demonstrates the following functionality:
// * key derivation via PBKDF2
//
// Hint: Internet Explorer 11 supports the webcrypto-api but has a non-standard promises implementation,
// therefore you have to change the code to work in IE 11 or use a proper polyfill.
//
// This example makes also use of the JS encoding API (https://encoding.spec.whatwg.org/)
// A proper polyfill for other browsers is "text-encoding" (https://github.com/inexorabletash/text-encoding)
//
// snippet by: innoq.com, simon.koelsch

// --- just a helper function for debug purposes
// converts an arraybuffer containing Uint8Array data to a hexstring
function ab2hex(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var hex = "";
  for (var i=0; i<byteArray.byteLength; i++) {
    hex += byteArray[i].toString(16);
  }
  return hex;
}

var encoder = new TextEncoder("utf-8");

var cryptoSubtle = window.crypto.subtle;

var deriveIterations = 1000;
var deriveHash = {name: 'SHA-1'};
var deriveSalt = encoder.encode("test-salt");
var deriveAlgorithm = {name: 'PBKDF2', salt: deriveSalt, iterations: deriveIterations, hash: deriveHash};
var extractable = true;

var algorithm = {name: 'AES-CBC', length: 128};
var usages = ["encrypt", "decrypt"];

// input from the user, for example a password
// it is not likely that the user will be prompted with a native browser dialog like mentioned in the spec
var deriveFrom = "secret";
data = encoder.encode(deriveFrom);

cryptoSubtle.importKey('raw', data, deriveAlgorithm, extractable, ['deriveKey'])
.then(function(password) {

  console.log("succesfully used password in key import:", password);

  cryptoSubtle.deriveKey(deriveAlgorithm, password, algorithm, extractable, usages);
  .then(function (derivedKey) {

    console.log("succesfully derived key from password:", derivedKey);

    cryptoSubtle.exportKey('raw', derivedKey)
    .then(function(key) {
      console.log("Derived key:", ab2hex(key));
    });

  });
});
