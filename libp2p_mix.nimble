mode = ScriptMode.Verbose

packageName = "libp2p_mix"
version = "0.1.0"
author = "Status Research & Development GmbH"
description =
  "Mix protocol for nim-libp2p — anonymous routing with the Sphinx packet format"
license = "MIT"
entryPoints = @["libp2p_mix.nim", "examples/mix_ping_forward.nim"]
skipDirs = @["examples", "tests"]

# Pin nim-libp2p master until a release is tagged.
requires "nim >= 2.2.4",
  "https://github.com/vacp2p/nim-libp2p.git#c43199378f46d0aaf61be1cad1ee1d63e8f665d6",
  "chronicles >= 0.11.0", "chronos >= 4.2.2", "metrics", "nimcrypto >= 0.6.0",
  "stew >= 0.4.2", "results", "unittest2"

import os, strutils

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use
let lang = getEnv("NIMLANG", "c") # Which backend (c/cpp/js)
let compilerFlags = getEnv("NIMFLAGS", "") # Extra flags for the compiler
let verbose = getEnv("V", "") notin ["", "0"]

let cfg =
  " --styleCheck:usages --styleCheck:error" & (if verbose: "" else: " --verbosity:0") &
  " --skipUserCfg -f --threads:on --opt:speed"

proc runTest(filename: string, moreoptions: string = "") =
  var compileCmd = nimc & " " & lang & " " & cfg & " " & compilerFlags
  compileCmd &= " " & moreoptions

  exec compileCmd & " tests/" & filename
  exec "./tests/" & filename.toExe
  rmFile "tests/" & filename.toExe

proc buildExample(filename: string) =
  let cmd = nimc & " " & lang & " " & cfg & " " & compilerFlags & " --hints:off"
  exec cmd & " examples/" & filename
  let exeName = filename.changeFileExt("").toExe
  exec "./examples/" & exeName
  rmFile "examples/" & exeName

task test, "Run unit tests":
  for f in listFiles("tests"):
    let (_, name, ext) = f.splitFile
    if ext == ".nim" and name.startsWith("test_"):
      runTest(name)

task testComponent, "Run component (integration) tests":
  for f in listFiles("tests/component"):
    let (_, name, ext) = f.splitFile
    if ext == ".nim" and name.startsWith("test_"):
      runTest("component/" & name)

task testAll, "Run unit + component tests":
  exec "nimble test"
  exec "nimble testComponent"

task example, "Build and run the forwarded destination ping example":
  buildExample("mix_ping_forward.nim")

task exampleForward, "Build and run the forwarded destination ping example":
  buildExample("mix_ping_forward.nim")

task exampleMixNode, "Build and run the mix-node destination ping example":
  buildExample("mix_ping_mix_node.nim")
