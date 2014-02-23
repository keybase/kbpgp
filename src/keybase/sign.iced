{SHA512,alloc} = require '../hash'
K = require('../const').kb
{pack} = require './encode'

#==============

json_encode = ({header, body, json_encoding}) ->
  obj = { body, header }
  err = null
  payload = switch json_encoding
    when K.json_encoding.plain then JSON.stringify obj
    when K.json_encoding.msgpack then pack obj
    else err = new Error "bad json_encoding scheme: #{json_encoding}"
  [err, payload]

#==============

sign = ({key, type, body, hasher, progress_hook, json_encoding, include_body}, cb) ->
  # XXX Support RSA-PSS.  See Issue #4
  hasher = SHA512 unless hasher?
  json_encoding = K.json_encoding.msgpack unless json_encoding?
  header = 
    type : type
    version : K.versions.V1
    hasher : hasher.type
    padding : K.padding.EMSA_PCKS1_v1_5
    json_encoding : json_encoding
  [err,payload] = json_encode { json_encoding, header, body }
  unless err?
    await key.pad_and_sign payload, { hasher }, defer sig
    output = { header, sig }
    output.body = body if include_body
  cb err, output

#==============

verify = ({type, key, sig, body, progress_hook}, cb) ->
  # XXX Support RSA-PSS.  See Issue #4
  header = hd = sig.header
  json_encoding = header.json_encoding
  hasher = alloc header.hasher
  [err,payload] = json_encode { json_encoding, header, body }
  err = if err? then err
  else if hd.version isnt K.versions.V1 then new Error "unknown version: #{header.version}"
  else if hd.padding isnt K.padding.EMSA_PCKS1_v1_5 then new Error "unknown padding: #{header.padding}"
  else if type isnt hd.type then new Error "Unexpected sig type; wanted #{type}, got #{hd.type}"
  else null
  unless err?
    await key.verify_unpad_and_check_hash { sig : sig.sig, data : payload, hasher }, defer err
  cb err

#==============

exports.sign = sign
exports.verify = verify
exports.json_encode = json_encode

#==============



