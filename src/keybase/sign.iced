{SHA512,alloc} = require '../hash'
K = require('../const').kb
{pack} = require './encode'

#==============

sign = ({key, type, body, hasher, progress_hook}, cb) ->
  # XXX Support RSA-PSS.  See Issue #4
  hasher = SHA512 unless hasher?
  header = 
    type : type
    version : K.versions.V1
    hasher : hasher.type
    padding : K.padding.EMSA_PCKS1_v1_5

  payload = pack { body, header }
  sig = key.pad_and_sign payload, { hasher }
  output = { header, sig }
  cb null, output

#==============

verify = ({type, key, sig, body, progress_hook}, cb) ->
  # XXX Support RSA-PSS.  See Issue #4
  header = hd = sig.header
  payload = pack { body, header }
  hasher = alloc header.hasher
  err = if hd.version isnt K.versions.V1 then new Error "unknown version: #{header.version}"
  else if hd.padding isnt K.padding.EMSA_PCKS1_v1_5 then new Error "unknown padding: #{header.padding}"
  else if type isnt hd.type then new Error "Unexpected sig type; wanted #{type}, got #{hd.type}"
  else key.verify_unpad_and_check_hash sig.sig, payload, hasher
  cb err

#==============

exports.sign = sign
exports.verify = verify

#==============



