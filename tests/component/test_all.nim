# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Single entry point for component (integration) tests. Kept separate from
## unit `test_all` so process isolation and CI job splitting stay available.
##
## Individual files remain runnable for local debugging:
##   nim c -r tests/component/test_connection_api.nim

{.used.}

import std/os
import ../imports

importTests(currentSourcePath().parentDir())
