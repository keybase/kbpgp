C = require('../const').openpgp
K = require('../const').kb
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{calc_checksum} = require '../util'
{encrypt} = require '../cfb'
{Packet} = require './base'

#=================================================================================

class KeyMaterial extends Packet

  constructor : (@key) ->
    super()

  #--------------------------

  _write_public : (timestamp) ->
    pub = @key.pub.serialize()
    return { type : @key.type, pub, timestamp }

  #--------------------------

  write_public : (timestamp) ->
    body = @_write_public timestamp
    @frame_packet C.packet_tags.public_key, body

  #--------------------------

  write_private : ({password,timestamp,progress_hook}, cb) ->
    ret = @_write_public timestamp
    priv = @key.priv.serialize()
    if password?
      await triplesec.encrypt { key : password, data : priv, progress_hook }, defer err, epriv
      if err? then ret = null
      else
        ret.priv = 
          data : epriv
          encryption : K.key_encryption.triplesec_v1
    else
      ret.prev = 
        data : priv
        encryption : K.key_encryption.none

    if ret? then ret = @frame_packet C.packet_tags.public_key, ret
    cb err, ret

  #--------------------------
  
#=================================================================================

