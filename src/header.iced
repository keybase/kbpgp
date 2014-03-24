C = require './const'
pjs = require '../package.json'

exports.header = 
  version : C.header.version + " v#{pjs.version}"
  comment : C.header.comment


