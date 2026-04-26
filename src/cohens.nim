import std/[parseopt, strutils, sequtils, os]
import cohens/crypto
import cohens/encoding

const Usage = """
cohens - Cohen's cryptosystem (1998) CLI tool

Usage:
  cohens genkey  [-k:N] [-b:N] [-o:FILE]  Generate a private key (contains public key)
  cohens pubout  -i:FILE [-o:FILE]         Extract public key from private key
  cohens encrypt -k:FILE [-i:FILE] [-o:FILE]  Encrypt a file
  cohens decrypt -k:FILE [-i:FILE] [-o:FILE]  Decrypt a file
  cohens inspect FILE                      Inspect a PEM file

Options:
  -k:N        Security parameter for genkey (default: 10)
  -b:N        Noise multiplier B for u-values (default: 1000)
  -k:FILE     Key file for encrypt/decrypt
  -i:FILE     Input file (default: stdin)
  -o:FILE     Output file (default: stdout)
"""

proc writeOutput(data: string, path: string) =
  if path == "":
    stdout.write(data)
  else:
    writeFile(path, data)

proc readInput(path: string): string =
  if path == "":
    return stdin.readAll()
  else:
    return readFile(path)

proc cmdGenkey(args: seq[string]) =
  var k: int64 = 10
  var b: int64 = 1000
  var outFile = ""
  var p = initOptParser(args)
  for kind, key, val in p.getopt():
    case kind
    of cmdShortOption, cmdLongOption:
      case key
      of "k": k = parseBiggestInt(val).int64
      of "b": b = parseBiggestInt(val).int64
      of "o": outFile = val
      else: quit("Unknown option: " & key, 1)
    of cmdArgument: quit("Unexpected argument: " & key, 1)
    of cmdEnd: discard

  let (privateKey, publicKey) = generatePublicPrivateKeyPair(k, b)
  let data = serializePrivateKey(k, b, privateKey, publicKey)
  let pem = wrapPem(data, PrivateKeyLabel)
  writeOutput(pem, outFile)
  if outFile != "":
    stderr.writeLine("Wrote private key to " & outFile)

proc cmdPubout(args: seq[string]) =
  var inFile = ""
  var outFile = ""
  var p = initOptParser(args)
  for kind, key, val in p.getopt():
    case kind
    of cmdShortOption, cmdLongOption:
      case key
      of "i": inFile = val
      of "o": outFile = val
      else: quit("Unknown option: " & key, 1)
    of cmdArgument: quit("Unexpected argument: " & key, 1)
    of cmdEnd: discard

  if inFile == "":
    quit("Error: -i:<private key file> is required", 1)

  let pem = readFile(inFile)
  let (label, raw) = unwrapPem(pem)
  if label != PrivateKeyLabel:
    quit("Error: expected private key, got: " & label, 1)

  let priv = deserializePrivateKey(raw)
  let pubData = serializePublicKey(priv.k, priv.publicKey)
  let pubPem = wrapPem(pubData, PublicKeyLabel)
  writeOutput(pubPem, outFile)
  if outFile != "":
    stderr.writeLine("Wrote public key to " & outFile)

proc cmdEncrypt(args: seq[string]) =
  var keyFile = ""
  var inFile = ""
  var outFile = ""
  var p = initOptParser(args)
  for kind, key, val in p.getopt():
    case kind
    of cmdShortOption, cmdLongOption:
      case key
      of "k": keyFile = val
      of "i": inFile = val
      of "o": outFile = val
      else: quit("Unknown option: " & key, 1)
    of cmdArgument: quit("Unexpected argument: " & key, 1)
    of cmdEnd: discard

  if keyFile == "":
    quit("Error: -k:<key file> is required", 1)

  let keyPem = readFile(keyFile)
  let (label, keyRaw) = unwrapPem(keyPem)

  var publicKey: seq[int64]
  case label
  of PublicKeyLabel:
    publicKey = deserializePublicKey(keyRaw).publicKey
  of PrivateKeyLabel:
    publicKey = deserializePrivateKey(keyRaw).publicKey
  else:
    quit("Error: expected a key file, got: " & label, 1)

  let plaintext = readInput(inFile)
  let message = plaintext.toSeq().mapIt(it.ord.byte)
  let ciphertext = encrypt(message, publicKey)
  let ctData = serializeCiphertext(ciphertext)
  let ctPem = wrapPem(ctData, CiphertextLabel)
  writeOutput(ctPem, outFile)
  if outFile != "":
    stderr.writeLine("Wrote ciphertext to " & outFile)

proc cmdDecrypt(args: seq[string]) =
  var keyFile = ""
  var inFile = ""
  var outFile = ""
  var p = initOptParser(args)
  for kind, key, val in p.getopt():
    case kind
    of cmdShortOption, cmdLongOption:
      case key
      of "k": keyFile = val
      of "i": inFile = val
      of "o": outFile = val
      else: quit("Unknown option: " & key, 1)
    of cmdArgument: quit("Unexpected argument: " & key, 1)
    of cmdEnd: discard

  if keyFile == "":
    quit("Error: -k:<private key file> is required", 1)

  let keyPem = readFile(keyFile)
  let (label, keyRaw) = unwrapPem(keyPem)
  if label != PrivateKeyLabel:
    quit("Error: expected private key, got: " & label, 1)
  let priv = deserializePrivateKey(keyRaw)

  let ctPem = readInput(inFile)
  let (ctLabel, ctRaw) = unwrapPem(ctPem)
  if ctLabel != CiphertextLabel:
    quit("Error: expected ciphertext, got: " & ctLabel, 1)

  let ciphertext = deserializeCiphertext(ctRaw)
  let plaintext = decrypt(ciphertext, priv.p)
  let text = plaintext.mapIt(char(it)).join("")
  writeOutput(text, outFile)

proc cmdInspect(args: seq[string]) =
  if args.len == 0:
    quit("Error: expected a file path", 1)

  let pem = readFile(args[0])
  let (label, raw) = unwrapPem(pem)

  echo "Type: " & label
  case label
  of PrivateKeyLabel:
    let priv = deserializePrivateKey(raw)
    echo "Parameter k: " & $priv.k
    echo "Parameter B: " & $priv.b
    echo "Private key (p): " & $priv.p
    echo "Public key values: " & $priv.publicKey.len & " elements"
    if priv.publicKey.len > 0:
      echo "  First: " & $priv.publicKey[0]
      if priv.publicKey.len > 1:
        echo "  Last:  " & $priv.publicKey[^1]
  of PublicKeyLabel:
    let pub = deserializePublicKey(raw)
    echo "Parameter k: " & $pub.k
    echo "Public key values: " & $pub.publicKey.len & " elements"
    if pub.publicKey.len > 0:
      echo "  First: " & $pub.publicKey[0]
      if pub.publicKey.len > 1:
        echo "  Last:  " & $pub.publicKey[^1]
  of CiphertextLabel:
    let ct = deserializeCiphertext(raw)
    echo "Ciphertext blocks: " & $ct.len
    echo "Plaintext bytes: " & $(ct.len div 8)
  else:
    echo "Unknown PEM type"
  echo "Raw size: " & $raw.len & " bytes"

when isMainModule:
  var args: seq[string] = commandLineParams()
  if args.len == 0:
    echo Usage
    quit(0)

  let subcommand = args[0]
  let subArgs = args[1..^1]

  case subcommand
  of "genkey": cmdGenkey(subArgs)
  of "pubout": cmdPubout(subArgs)
  of "encrypt": cmdEncrypt(subArgs)
  of "decrypt": cmdDecrypt(subArgs)
  of "inspect": cmdInspect(subArgs)
  of "help", "--help", "-h": echo Usage
  else:
    stderr.writeLine("Unknown command: " & subcommand)
    echo Usage
    quit(1)