// RSA key generation Web Cryptography API Example Code Snippet
// (see http://www.w3.org/TR/WebCryptoAPI/)
//
// The code demonstrates the following functionality:
// * RSA key generation
// * JWK export
//
// Hint: Internet Explorer 11 supports the webcrypto-api but has a non-standard promises implementation,
// therefore you have to change the code to work in IE 11 or use a proper polyfill.
//
// snippet by: innoq.com, simon.koelsch

var cryptoSubtle = window.crypto.subtle;

var hashAlgorithm = {name: 'SHA-1'};
var algorithm = {name: 'RSASSA-PKCS1-v1_5', hash: hashAlgorithm, modulusLength: 1024, publicExponent: new Uint8Array([1,0,1])};
var extractable = true;
var usages = ["sign", "verify"];

cryptoSubtle.generateKey(algorithm, extractable, usages)
.then(function(keypair) {

  console.log("Keypair generated: ", keypair);

  cryptoSubtle.exportKey('jwk',keypair.publicKey)
  .then(function(key) {
    console.log(key);
  });

});
