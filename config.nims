--styleCheck:
  usages
--styleCheck:
  error
--mm:
  refc

# Allow `import libp2p_mix/X` and `import ./tools/X` from any subdirectory
switch("path", thisDir())
switch("nimcache", "nimcache")

# begin Nimble config (version 2)
--noNimblePath
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
