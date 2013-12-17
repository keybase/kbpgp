
{burn} = require './burn'
processor = require './processor'

#-----------------------------

exports.SignatureEngine = class SignatureEngine

  constructor : ({@km}) ->
  get_km      : -> @km
  box         : (args, cb) -> burn args, cb
  unbox       : (msg, cb) -> 
    eng = new processor.Message km
    eng.parse_and_process msg.body, cb

#-----------------------------

