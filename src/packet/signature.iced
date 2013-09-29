
{Packet} = require './base'
C = require('../const').openpgp
{uint_to_buffer,encode_length,make_time_packet} = require '../util'
{SHA512} = require '../hash'

#===========================================================

class Signature extends Packet

  #---------------------

  constructor : (@key, @hash = SHA512) ->

  #---------------------

  subpacket : (type, buf) ->
    Buffer.concat [
      new Buffer([type]),
      encode_length(buf.length+1),
      buf
    ]

  #---------------------

  # See write_message_signature in packet.signature.js
  write : (sigtype, data, cb) ->
    dsp = @subpacket(C.sig_subpacket.creation_time, make_time_packet())
    isp = @subpacket(C.sig_subpacket.issuer, key.get_key_id())
    result = Buffer.concat [ 
      new Buffer([ C.versions.signature.V4, sigtype, @key.type ]),
      uint_to_buffer(16, (dsp.length + isp.length)),
      dsp,
      isp
    ]

    trailer = Buffer.concat [
      new Buffer([ C.versions.signature.V4, 0xff ]),
      uint_to_buffer(32, result.length)
    ]

    payload = Buffer.concat [ data, result, trailer ]
    hash = @hash payload
    sig = @key.pad_and_sign payload, { @hash }
    result2 = Buffer.concat [
      new Buffer([0,0, hash.readUInt8(0), hash.readUInt8(1) ]),
      sig
    ]
    results = Buffer.concat [ result, result2 ]
    ret = @frame_packet(C.packet_tags.signature, results)
    cb null, ret

#===========================================================

