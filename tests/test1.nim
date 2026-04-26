# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest
import std/[sequtils, strutils]
import cohens/crypto

test "A message encrypted by Cohen's is decrypted correctly":
  var k = 10
  var plaintext = "Hello, Nim!"
  var (privateKey, publicKey) = generatePublicPrivateKeyPair(k)
  var ciphertext: seq[int64] = encrypt(plaintext.toSeq().mapIt(it.ord.byte), publicKey)
  var decryptedMessage: seq[byte] = decrypt(ciphertext, privateKey)
  check(decryptedMessage.mapIt(it.char).join("") == plaintext)

test "Decryption with wrong private key fails":
  var k = 10
  var plaintext = "Hello, Nim!"
  var (_, publicKey) = generatePublicPrivateKeyPair(k)
  var (privateKey2, _) = generatePublicPrivateKeyPair(k)
  var ciphertext: seq[int64] = encrypt(plaintext.toSeq().mapIt(it.ord.byte), publicKey)
  var decryptedMessage: seq[byte] = decrypt(ciphertext, privateKey2)
  check(decryptedMessage.mapIt(it.char).join("") != plaintext)