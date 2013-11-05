mods = [ 
 require("./keymanager"),
 require("./basex"),
 require("./openpgp/burner")
]
for m in mods
  for k,v of m
    exports[k] = v
exports.ASP = require('./util').ASP
exports.rand = require('./rand')
exports.const = require './const'