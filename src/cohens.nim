import cohens/crypto

when isMainModule:
  var k = 10
  var privateKey = generatePrivateKey()
  var publicKey = generatePublicKey(privateKey, k)

  var originalMessage = "Hello, Nim!"
  var encryptedMessage: seq[int64] = encrypt(originalMessage.toSeq().mapIt(it.ord.byte), publicKey)
  var decryptedMessage: seq[char] = decrypt(encryptedMessage, privateKey).mapIt(it.char)

  echo "Original Message: ", originalMessage
  echo "Encrypted Message: ", encryptedMessage
  echo "Decrypted Message: ", decryptedMessage.join("")