# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Compile-time helpers that pull every `test_*.nim` in a directory into one
## translation unit. Used by `test_all.nim` entry points so CI compiles the
## libp2p/chronos/stew dependency tree once instead of once per test file
## (see logos-co/nim-libp2p-mix#17).

import std/[algorithm, macros, os, strutils]

macro importTests*(dir: static string): untyped =
  ## Import every `test_*.nim` under `dir` (non-recursive), excluding
  ## `test_all.nim` itself. Sorted for deterministic compile order.
  ##
  ## Generates same-directory relative imports (`./test_foo`) so resolution
  ## is independent of the absolute checkout path that `walkDir` returns.
  ## Callers must live in `dir` (both `test_all.nim` entry points do).
  result = newStmtList()
  var names: seq[string] = @[]
  for kind, path in walkDir(dir):
    if kind != pcFile:
      continue
    let (_, name, ext) = splitFile(path)
    if ext == ".nim" and name.startsWith("test_") and name != "test_all":
      names.add(name)
  sort(names)
  for name in names:
    result.add nnkImportStmt.newTree(newLit("./" & name))
