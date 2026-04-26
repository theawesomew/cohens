import std/[monotimes, sequtils, strutils, stats, times]
import cohens/crypto
import cohens/encoding

const
  Iterations = 1000
  K: int64 = 10
  Plaintext = "Hello, Cohen's cryptosystem! This is a benchmark message."

func formatDuration(us: float): string =
  if us >= 1000.0:
    return (us / 1000.0).formatFloat(ffDecimal, 3) & " ms"
  elif us >= 1.0:
    return us.formatFloat(ffDecimal, 3) & " us"
  else:
    return (us * 1000.0).formatFloat(ffDecimal, 1) & " ns"

template bench(name: string, n: int, body: untyped) =
  var timings: RunningStat
  for i in 0..<n:
    let t0 = getMonoTime()
    body
    let dt = (getMonoTime() - t0).inNanoseconds.float / 1000.0 # microseconds
    timings.push(dt)
  echo name.alignLeft(30) &
    "mean=" & formatDuration(timings.mean).alignLeft(14) &
    "min=" & formatDuration(timings.min).alignLeft(14) &
    "max=" & formatDuration(timings.max).alignLeft(14) &
    "stddev=" & formatDuration(timings.standardDeviation).alignLeft(14) &
    "n=" & $n

when isMainModule:
  echo "Cohen's Cryptosystem Benchmarks"
  echo "================================"
  echo "k=" & $K & "  plaintext=" & $Plaintext.len & " bytes  iterations=" & $Iterations
  echo ""

  # -- Key generation --
  var privKey: int64
  var pubKey: seq[int64]
  bench("genkey", Iterations):
    let (pk, pub) = generatePublicPrivateKeyPair(K)
    privKey = pk
    pubKey = pub

  # -- Encryption --
  let msgBytes = Plaintext.toSeq().mapIt(it.ord.byte)
  var ciphertext: seq[int64]
  bench("encrypt", Iterations):
    ciphertext = encrypt(msgBytes, pubKey)

  # -- Decryption --
  var decrypted: seq[byte]
  bench("decrypt", Iterations):
    decrypted = decrypt(ciphertext, privKey)

  assert decrypted.mapIt(char(it)).join("") == Plaintext, "Decryption sanity check failed"

  # -- Encoding: private key serialize/deserialize --
  bench("serialize privkey", Iterations):
    discard serializePrivateKey(K, privKey, pubKey)

  let privRaw = serializePrivateKey(K, privKey, pubKey)
  bench("deserialize privkey", Iterations):
    discard deserializePrivateKey(privRaw)

  # -- Encoding: PEM wrap/unwrap --
  let privPem = wrapPem(privRaw, PrivateKeyLabel)
  bench("wrapPem (privkey)", Iterations):
    discard wrapPem(privRaw, PrivateKeyLabel)

  bench("unwrapPem (privkey)", Iterations):
    discard unwrapPem(privPem)

  # -- Encoding: ciphertext serialize/deserialize --
  bench("serialize ciphertext", Iterations):
    discard serializeCiphertext(ciphertext)

  let ctRaw = serializeCiphertext(ciphertext)
  bench("deserialize ciphertext", Iterations):
    discard deserializeCiphertext(ctRaw)

  # -- Full round-trip: genkey + encrypt + PEM encode --
  bench("full encrypt pipeline", Iterations):
    let (pk, pub) = generatePublicPrivateKeyPair(K)
    let ct = encrypt(msgBytes, pub)
    let raw = serializeCiphertext(ct)
    discard wrapPem(raw, CiphertextLabel)

  # -- Full round-trip: PEM decode + decrypt --
  let ctPem = wrapPem(ctRaw, CiphertextLabel)
  bench("full decrypt pipeline", Iterations):
    let (_, data) = unwrapPem(ctPem)
    let ct = deserializeCiphertext(data)
    discard decrypt(ct, privKey)

  echo ""
  echo "Done."
