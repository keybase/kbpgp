mods = [ 
  require("./keygen") 
]
for m in mods
  for k,v of m
    exports[k] = v
