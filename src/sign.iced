{SHA512,alloc} = require './hash'
K = require('./const').kb
{pack} = require './kbpacket/encode'

#==============

sign = ({key, type, body, hash, progress_hook}, cb) ->
  # XXX Support RSA-PSS.  See Issue #4
  hash = SHA512 unless hash?
  header = 
    type : type
    version : K.versions.V1
    hash : hash.type
    padding : K.padding.EMSA_PCKS1_v1_5

  payload = pack { body, header }
  sig = key.pad_and_sign payload, { hash : hash }
  output = { header, sig }
  cb null, output

#==============

verify = ({type, key, sig, body, progress_hook}, cb) ->
  # XXX Support RSA-PSS.  See Issue #4
  header = hd = sig.header
  payload = pack { body, header }
  hash = alloc header.hash
  err = if hd.version isnt K.versions.V1 then new Error "unknown version: #{header.version}"
  else if hd.padding isnt K.padding.EMSA_PCKS1_v1_5 then new Error "unknown padding: #{header.padding}"
  else if type isnt hd.type then new Error "Unexpected sig type; wanted #{type}, got #{hd.type}"
  else key.verify_unpad_and_check_hash sig.sig, payload, hash
  cb err

#==============

exports.sign = sign
exports.verify = verify

#==============



