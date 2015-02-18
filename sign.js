// ECDSA Sign/Verify Web Cryptography API Example Code Snippet
// (see http://www.w3.org/TR/WebCryptoAPI/)
//
// The code demonstrates the following functionality:
// * ECDSA key generation
// * JWK export
// * sign / verify
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

var hashAlgorithm = {name: 'SHA-1'};
var algorithm = {name: 'ECDSA', namedCurve: 'P-256', hash: hashAlgorithm};
var extractable = true;
var usages = ["sign", "verify"];

cryptoSubtle.generateKey(algorithm, extractable, usages)
.then(function(keypair) {

  console.log("Keypair generated: ", keypair);

  //TODO track bug: https://bugzilla.mozilla.org/show_bug.cgi?id=1133698
  cryptoSubtle.exportKey('jwk', keypair.publicKey)
  .then(function(exportedKey) {
    console.log("Public key exported as JWK:", exportedKey);
  }, function(error) {
    console.log("Key export as jwk failed:",error);
  });

  var toSign = "This is a text to sign.";
  var data = encoder.encode(toSign);

  cryptoSubtle.sign(algorithm, keypair.privateKey, data)
  .then(function(signature) {

    console.log("Signature:",ab2hex(signature));

    cryptoSubtle.verify(algorithm, keypair.publicKey, signature, data)
    .then(function(result) {

      console.log("Signature is valid:", result);

      var brokenData = encoder.encode(toSign + "foo");

      cryptoSubtle.verify(algorithm, publicKey, signature, brokenData)
      .then(function(brokenResult) {
        console.log("Signature for broken data is valid:", brokenResult);
      });
    });
  });

});
