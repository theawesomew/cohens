# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest
import std/[sequtils, strutils]
import cohens/crypto
import cohens/encoding

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

test "Private key PEM round-trip":
  let k: int64 = 10
  let b: int64 = 5000
  let (priv, pub) = generatePublicPrivateKeyPair(k, b)
  let raw = serializePrivateKey(k, b, priv, pub)
  let pem = wrapPem(raw, PrivateKeyLabel)
  let (label, data) = unwrapPem(pem)
  check(label == PrivateKeyLabel)
  let decoded = deserializePrivateKey(data)
  check(decoded.k == k)
  check(decoded.b == b)
  check(decoded.p == priv)
  check(decoded.publicKey == pub)

test "Public key PEM round-trip":
  let k: int64 = 10
  let (_, pub) = generatePublicPrivateKeyPair(k)
  let raw = serializePublicKey(k, pub)
  let pem = wrapPem(raw, PublicKeyLabel)
  let (label, data) = unwrapPem(pem)
  check(label == PublicKeyLabel)
  let decoded = deserializePublicKey(data)
  check(decoded.k == k)
  check(decoded.publicKey == pub)

test "Ciphertext PEM round-trip":
  let k: int64 = 10
  let (_, pub) = generatePublicPrivateKeyPair(k)
  let msg = "Test".toSeq().mapIt(it.ord.byte)
  let ct = encrypt(msg, pub)
  let raw = serializeCiphertext(ct)
  let pem = wrapPem(raw, CiphertextLabel)
  let (label, data) = unwrapPem(pem)
  check(label == CiphertextLabel)
  let decoded = deserializeCiphertext(data)
  check(decoded == ct)

test "int64 big-endian round-trip":
  let values = @[0'i64, 1, -1, int64.high, int64.low, 488892]
  for v in values:
    let bytes = int64ToBytesBE(v)
    let back = bytesToInt64BE(bytes)
    check(back == v)