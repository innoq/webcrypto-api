// AES-CBC Web Cryptography API Example Code Snippet
// (see http://www.w3.org/TR/WebCryptoAPI/)
//
// The code demonstrates the following functionality:
// * key generation
// * key export / import
// * encryption / decryption
// * use random values as iv
//
// Hint: Internet Explorer 11 supports the webcrypto-api but has a non-standard promises implementation,
// therefore you have to change the code to work in IE 11 or use a proper polyfill.
//
// This example makes also use of the JS encoding API (https://encoding.spec.whatwg.org/)
// A proper polyfill for other browsers is "text-encoding" (https://github.com/inexorabletash/text-encoding)
//
// snippet by: innoq.com, simon.koelsch

var decoder = new TextDecoder("utf-8");
var encoder = new TextEncoder("utf-8");

var cryptoSubtle = window.crypto.subtle;

// get random iv
var iv = window.crypto.getRandomValues(new Uint8Array(16));
console.log("using a random iv:", iv);

var algorithm = {name: 'AES-CBC', length: 128, iv: iv};
var extractable = true;
var usages = ["encrypt", "decrypt"];

cryptoSubtle.generateKey(algorithm, extractable, usages)
.then(function(key) {

  console.log("Key generated: ", key);

  cryptoSubtle.exportKey("raw", key)
  .then(function(exportedKey) {

    console.log("exported raw key: ", new Uint8Array(exportedKey));

    // start encryption with generated key

    var text = "Encrypt me!";
    console.log("String to encrypt: ", text);

    cryptoSubtle.encrypt(algorithm, key, encoder.encode(text))
    .then(function(encryptedText) {

      var dataViewEnc = new DataView(encryptedText);
      console.log("Encrypted string: ", decoder.decode(dataViewEnc));

      // import the exported  key and use it for decryption

      cryptoSubtle.importKey("raw", exportedKey, algorithm, extractable, usages)
      .then(function(keyImport) {

        cryptoSubtle.decrypt(algorithm, keyImport, encryptedText)
        .then(function(decrypted){
          var dataView = new DataView(decrypted);
          console.log("Decrypted string: ", decoder.decode(dataView));
        });

      });
    });
  });
});
