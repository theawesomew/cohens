import std/[math, sequtils, sugar, random, enumerate, strutils]

randomize()

func `modu`(a, b: int64): int64 =
  let r = a mod b
  return if r < 0: r + b else: r

proc generatePrivateKey(): int64 =
  # Generate a random private key (a large integer)
  return rand(1_000_000).int64

proc generatePublicKey(p: int64, k: int64): seq[int64] =
  var r: Rand = initRand()
  let uValues: seq[int64] = ((0.int64)..k).toSeq().map(x => r.rand(-1000..1000).int64)
  let vValues: seq[int64] = ((0.int64)..k).toSeq().map(x => r.rand(0..int(ceil(p/(2*k)))).int64)

  return zip(uValues, vValues).mapIt(it[0] * p + it[1])

proc generatePublicPrivateKeyPair* (k: int64): (int64, seq[int64]) =
  let privateKey = generatePrivateKey()
  let publicKey = generatePublicKey(privateKey, k)
  return (privateKey, publicKey)

proc encrypt*(message: seq[byte], publicKey: var seq[int64]): seq[int64] =
  result = newSeq[int64](message.len * 8)
  var r: Rand = initRand()
  let k = publicKey.len

  for i, m in enumerate(message):
    for j in 0..<8:
      r.shuffle(publicKey)
      let selection = publicKey[0..((k div 2) - 1)]
      let sum = selection.sum()
      let bit = ((0x01.byte shl (7 - j)) and m) shr (7 - j)

      if bit == 1:
        result[i * 8 + j] = sum * -1
      else:
        result[i * 8 + j] = sum


proc decrypt*(ciphertext: seq[int64], privateKey: int64): seq[byte] =
  result = newSeq[byte](ciphertext.len div 8)
  var accum = 0
  var currentByte: byte = 0
  for c in ciphertext:
    let r: int64 = modu(c, privateKey)

    if r < (privateKey div 2):
      currentByte = (currentByte shl 1) or 0x00
    else:
      currentByte = (currentByte shl 1) or 0x01

    accum += 1

    if accum mod 8 == 0:
      result[(accum div 8) - 1] = currentByte
      currentByte = 0