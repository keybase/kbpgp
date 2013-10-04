mods = [ 
 require("./keygen"),
 require("./basex")
]
for m in mods
  for k,v of m
    exports[k] = v
