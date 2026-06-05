mode = ScriptMode.Verbose

packageName = "libp2p_mix"
version = "0.1.0"
author = "Status Research & Development GmbH"
description =
  "Mix protocol for nim-libp2p — anonymous routing with the Sphinx packet format"
license = "MIT"
skipDirs = @["examples", "tests"]

requires "nim >= 2.2.4",
  # Pinned to release/v2.0.0 tip (3 patch commits past the v2.0.0 commit).
  # vacp2p/nim-libp2p has no v2.0.0 git tag yet; SHA-pin until they publish one.
  "https://github.com/vacp2p/nim-libp2p.git#c43199378f46d0aaf61be1cad1ee1d63e8f665d6",
  "chronicles >= 0.11.0",
  "chronos >= 4.2.2",
  "metrics",
  "nimcrypto >= 0.6.0",
  "stew >= 0.4.2",
  "results",
  "unittest2"

import os, strutils

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use
let lang = getEnv("NIMLANG", "c") # Which backend (c/cpp/js)
let flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler
let verbose = getEnv("V", "") notin ["", "0"]

let cfg =
  " --styleCheck:usages --styleCheck:error" & (if verbose: "" else: " --verbosity:0") &
  " --skipUserCfg --threads:on --opt:speed" & " -d:libp2p_mix_experimental_exit_is_dest"
  # `-f` (force recompile) was previously here. Dropped so test binaries
  # share the nimcache: each subsequent test in `nimble test` /
  # `nimble testComponent` reuses compiled libp2p / chronos / stew object
  # files from the first test, cutting per-test compile time substantially.
  # Safe because every test invokes `runTest(name)` with no per-test
  # compile flag overrides — all tests build with identical `cfg`, so
  # cache hits are flag-correct.

proc runTest(filename: string, moreoptions: string = "") =
  var compileCmd = nimc & " " & lang & " " & cfg & " " & flags
  compileCmd &= " " & moreoptions

  exec compileCmd & " tests/" & filename
  exec "./tests/" & filename.toExe
  rmFile "tests/" & filename.toExe

proc buildExample(filename: string) =
  let cmd = nimc & " " & lang & " " & cfg & " " & flags & " --hints:off"
  exec cmd & " examples/" & filename
  let exeName = filename.changeFileExt("").toExe
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

task example, "Build and run the mix_ping example":
  buildExample("mix_ping.nim")
