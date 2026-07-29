# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Single entry point for unit tests. Importing each suite registers it with
## unittest2; one `nim c` builds all deps once (see #17).
##
## Individual files remain runnable for local debugging:
##   nim c -r tests/test_crypto.nim

{.used.}

import std/os
import ./imports

importTests(currentSourcePath().parentDir())
