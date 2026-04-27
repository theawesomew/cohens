import std/[base64, strutils]

const
  PrivateKeyLabel* = "COHEN PRIVATE KEY"
  PublicKeyLabel* = "COHEN PUBLIC KEY"
  CiphertextLabel* = "COHEN MESSAGE"

# -- Endian helpers --

func int64ToBytesBE*(val: int64): array[8, byte] =
  let v = cast[uint64](val)
  result[0] = byte((v shr 56) and 0xFF)
  result[1] = byte((v shr 48) and 0xFF)
  result[2] = byte((v shr 40) and 0xFF)
  result[3] = byte((v shr 32) and 0xFF)
  result[4] = byte((v shr 24) and 0xFF)
  result[5] = byte((v shr 16) and 0xFF)
  result[6] = byte((v shr 8) and 0xFF)
  result[7] = byte(v and 0xFF)

func bytesToInt64BE*(data: openArray[byte]): int64 =
  var v: uint64 = 0
  v = v or (uint64(data[0]) shl 56)
  v = v or (uint64(data[1]) shl 48)
  v = v or (uint64(data[2]) shl 40)
  v = v or (uint64(data[3]) shl 32)
  v = v or (uint64(data[4]) shl 24)
  v = v or (uint64(data[5]) shl 16)
  v = v or (uint64(data[6]) shl 8)
  v = v or uint64(data[7])
  result = cast[int64](v)

# -- Serialization helpers --

func serializeInt64Seq(values: seq[int64]): string =
  result = newString(values.len * 8)
  for i, v in values:
    let b = int64ToBytesBE(v)
    for j in 0..7:
      result[i * 8 + j] = char(b[j])

func deserializeInt64Seq(data: string, offset: int, count: int): seq[int64] =
  result = newSeq[int64](count)
  for i in 0..<count:
    var buf: array[8, byte]
    for j in 0..7:
      buf[j] = byte(data[offset + i * 8 + j])
    result[i] = bytesToInt64BE(buf)

# -- Private key: [8B k] [8B b] [8B p] [8B * (k+1) public key values] --

func serializePrivateKey*(k, b, p: int64, publicKey: seq[int64]): string =
  var buf = newStringOfCap(24 + publicKey.len * 8)
  for byt in int64ToBytesBE(k): buf.add(char(byt))
  for byt in int64ToBytesBE(b): buf.add(char(byt))
  for byt in int64ToBytesBE(p): buf.add(char(byt))
  buf.add(serializeInt64Seq(publicKey))
  return buf

func deserializePrivateKey*(data: string): tuple[k, b, p: int64, publicKey: seq[int64]] =
  var buf: array[8, byte]
  for j in 0..7: buf[j] = byte(data[j])
  result.k = bytesToInt64BE(buf)
  for j in 0..7: buf[j] = byte(data[8 + j])
  result.b = bytesToInt64BE(buf)
  for j in 0..7: buf[j] = byte(data[16 + j])
  result.p = bytesToInt64BE(buf)
  let count = (data.len - 24) div 8
  result.publicKey = deserializeInt64Seq(data, 24, count)

# -- Public key: [8B k] [8B * (k+1) public key values] --

func serializePublicKey*(k: int64, publicKey: seq[int64]): string =
  var buf = newStringOfCap(8 + publicKey.len * 8)
  for byt in int64ToBytesBE(k): buf.add(char(byt))
  buf.add(serializeInt64Seq(publicKey))
  return buf

func deserializePublicKey*(data: string): tuple[k: int64, publicKey: seq[int64]] =
  var buf: array[8, byte]
  for j in 0..7: buf[j] = byte(data[j])
  result.k = bytesToInt64BE(buf)
  let count = (data.len - 8) div 8
  result.publicKey = deserializeInt64Seq(data, 8, count)

# -- Ciphertext: [8B * N values] --

func serializeCiphertext*(ct: seq[int64]): string =
  return serializeInt64Seq(ct)

func deserializeCiphertext*(data: string): seq[int64] =
  let count = data.len div 8
  return deserializeInt64Seq(data, 0, count)

# -- PEM wrapping --

func wrapPem*(data: string, label: string): string =
  let encoded = encode(data)
  var lines: seq[string] = @["-----BEGIN " & label & "-----"]
  var i = 0
  while i < encoded.len:
    let endIdx = min(i + 64, encoded.len)
    lines.add(encoded[i..<endIdx])
    i += 64
  lines.add("-----END " & label & "-----")
  return lines.join("\n") & "\n"

func unwrapPem*(pem: string): tuple[label: string, data: string] =
  let lines = pem.strip().splitLines()
  if lines.len < 2:
    raise newException(ValueError, "Invalid PEM: too few lines")
  let header = lines[0]
  let footer = lines[^1]
  if not header.startsWith("-----BEGIN ") or not header.endsWith("-----"):
    raise newException(ValueError, "Invalid PEM header: " & header)
  if not footer.startsWith("-----END ") or not footer.endsWith("-----"):
    raise newException(ValueError, "Invalid PEM footer: " & footer)
  result.label = header[11..^6]
  let endLabel = footer[9..^6]
  if result.label != endLabel:
    raise newException(ValueError, "PEM label mismatch: " & result.label & " vs " & endLabel)
  let b64 = lines[1..^2].join("")
  result.data = decode(b64)
