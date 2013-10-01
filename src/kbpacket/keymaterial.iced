K = require('../const').kb
triplesec = require 'triplesec'
{SHA512} = require '../hash'
{native_rng} = triplesec.prng
{Packet} = require './base'
{pack,bencode} = require './encode'

#=================================================================================

class KeyMaterial extends Packet

  constructor : ({@key, @timestamp, @userid, @passphrase } ) ->
    super()

  #--------------------------

  _write_public : () ->
    pub = @key.pub.serialize()
    return { type : @key.type, pub, @timestamp }

  #--------------------------

  write_public : () ->
    body = @_write_public()
    @frame_packet K.packet_tags.public_key, body

  #--------------------------

  write_private : ({progress_hook}, cb) ->
    await @_write_private { progress_hook }, defer err, ret 
    if ret? then ret = @frame_packet K.packet_tags.public_key, ret
    cb err, ret

  #--------------------------

  _write_private : ({progress_hook}, cb) ->
    ret = @_write_public()
    priv = @key.priv.serialize()

    if @passphrase?
      await triplesec.encrypt { key : @passphrase, data : priv, progress_hook }, defer err, epriv
      if err? then ret = null
      else
        ret.priv = 
          data : epriv
          encryption : K.key_encryption.triplesec_v1
    else
      ret.priv = 
        data : priv
        encryption : K.key_encryption.none

    cb err, ret

  #--------------------------

  _encode_keys : ({progress_hook}, sig, cb) ->
    await @_write_private { progress_hook }, defer err, priv
    pub = @_write_public()
    ret = null
    {private_key, public_key} = K.message_types
    # XXX always binary-encode for now (see Issue #7)
    unless err?
      ret = 
        private : bencode(private_key, { sig, @userid, key : priv }),
        public  : bencode(public_key,  { sig, @userid, key : pub })
    cb err, ret

  #--------------------------

  _self_sign_key : ( { progress_hook }, cb) ->
    # XXX factor this all out.  See Issue #8
    # XXX change to RSA-PSS.  See Issue #4
    hash = SHA512
    header = 
      type : K.signatures.self_sign_key
      version : K.versions.V1
      hash : SHA512.type
      padding : K.padding.EMSA_PCKS1_v1_5
    body =  { @userid, key : @_write_public() }

    payload = pack { body, header }
    sig = @key.pad_and_sign payload, { hash }
    cb null, { header, sig }

  #--------------------------

  export_keys : ({armor, progress_hook}, cb) ->
    ret = err = null
    await @_self_sign_key {progress_hook}, defer err, sig
    unless err?
      await @_encode_keys { progress_hook }, sig, defer err, ret
    cb err, ret

  #--------------------------

  
#=================================================================================

exports.KeyMaterial = KeyMaterial
