mods = [ 
 require("./keymanager"),
 require("./basex")
]
for m in mods
  for k,v of m
    exports[k] = v
exports.ASP = require('./util').ASP
