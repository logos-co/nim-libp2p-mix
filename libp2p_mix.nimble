mode = ScriptMode.Verbose

packageName = "libp2p_mix"
version = "0.1.0"
author = "Status Research & Development GmbH"
description =
  "Mix protocol for nim-libp2p — anonymous routing with the Sphinx packet format"
license = "MIT"
skipDirs = @["examples", "tests"]

requires "nim >= 2.2.4",
  "libp2p >= 2.2.1", "chronicles >= 0.11.0", "chronos >= 4.2.2", "metrics",
  "nimcrypto >= 0.6.0", "stew >= 0.4.2", "results", "unittest2"

import os, strutils

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use
let lang = getEnv("NIMLANG", "c") # Which backend (c/cpp/js)
let flags = getEnv("NIMFLAGS", "") # Extra flags for the compiler
let verbose = getEnv("V", "") notin ["", "0"]
let cxxRuntime =
  when defined(macosx):
    " --passL:-lc++"
  elif defined(posix):
    " --passL:-lstdc++"
  else:
    ""

let cfg =
  " --styleCheck:usages --styleCheck:error" & (if verbose: "" else: " --verbosity:0") &
  " --skipUserCfg -f --threads:on --opt:speed" &
  " -d:libp2p_mix_experimental_exit_is_dest" & cxxRuntime

proc runTest(filename: string, moreoptions: string = "") =
  var compileCmd = nimc & " " & lang & " " & cfg & " " & flags
  compileCmd &= " " & moreoptions

  exec compileCmd & " tests/" & filename
  exec "./tests/" & filename.toExe
  rmFile "tests/" & filename.toExe

proc buildExample(filename: string, moreoptions: string = "") =
  let cmd = nimc & " " & lang & " " & cfg & " " & flags & " --hints:off " & moreoptions
  exec cmd & " examples/" & filename
  let exeName = filename.changeFileExt("").toExe
  rmFile "examples/" & exeName

# Unit and component suites each compile as a single binary via test_all.nim
# (imports every test_*.nim in that directory). That compiles the shared
# libp2p/chronos/stew tree once per suite instead of once per file — the main
# CI wall-clock win from #17. Individual test_*.nim files remain runnable
# standalone for local debugging.
task test, "Run unit tests":
  runTest("test_all")

task testComponent, "Run component (integration) tests":
  runTest("component/test_all")

task testAll, "Run unit + component tests":
  exec "nimble test"
  exec "nimble testComponent"

task example, "Build and run the mix_ping example":
  buildExample("mix_ping.nim")

task benchmarkBuild, "Compile-check the -d:enable_mix_benchmarks code paths":
  # No regular build sets this flag, so these paths go unchecked (see #27).
  buildExample("mix_ping.nim", "-d:enable_mix_benchmarks")
