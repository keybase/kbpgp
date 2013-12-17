
#=========================================================

mods = [
  require("pgp-utils").util
  require("./openpgp/util")
]
for m in mods
  for k,v of m
    exports[k] = v

#=========================================================
