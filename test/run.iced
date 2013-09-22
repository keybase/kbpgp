
argv = require('optimist').argv
wl = if argv._.length > 0 then argv._ else null
require('iced-test').run { mainfile : __filename, whitelist : wl, files_dir : "files" }
