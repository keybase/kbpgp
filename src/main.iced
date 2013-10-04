

mods = [ "./keygen" ]
for m in mods
  for k,v of require(m)
    exports[k] = v
