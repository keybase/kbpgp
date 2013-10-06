
{Packet} = require './base'
C = require('../const').openpgp
{uint_to_buffer,encode_length,make_time_packet} = require '../util'
{alloc_or_throw,SHA512} = require '../hash'
asymmetric = require '../asymmetric'

#===========================================================

class Signature extends Packet

  #---------------------

  constructor : (@keymaterial, @hash = SHA512) ->
    @key = @keymaterial.key

  #---------------------

  subpacket : (type, buf) ->
    Buffer.concat [
      encode_length(buf.length+1),
      new Buffer([type]),
      buf
    ]

  #---------------------

  # See write_message_signature in packet.signature.js
  write : (sigtype, data, cb) ->
    dsp = @subpacket(C.sig_subpacket.creation_time, make_time_packet())
    isp = @subpacket(C.sig_subpacket.issuer, @keymaterial.get_key_id())
    result = Buffer.concat [ 
      new Buffer([ C.versions.signature.V4, sigtype, @key.type, @hash.type ]),
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

  #-----------------
  
  @parse : (slice) -> (new Parser slice).parse()

  #-----------------
  
#===========================================================

exports.Signature = Signature

#===========================================================

class Parser

  constructor : (@slice) ->

  parse_v3 : () ->
    throw new error "Bad one-octet length" unless @slice.read_uint8() is 5
    @type = @slice.read_uint8()
    @time = new Date (@slice.read_uint32() * 1000)
    @sig_data = @slice.peek_rest_to_buffer()
    @key_id = @slice.read_buffer 8
    @public_key_class = asymmetric.get_class @slice.read_uint8()
    @hash_alg = alloc_or_throw @slice.read_uint8()
    @signed_hash_value_hash = @slice.read_uint16()
    @sig = @public_key_class.parse_sig @slice

  parse_v4 : () ->
    @type = @slice.read_uint8()
    @public_key_class = asymmetric.get_class @slice.read_uint8()
    @hash_alg = alloc_or_throw @slice.read_uint8()
    hashed_subpacket_count = @slice.read_uint16()
    end = @slice.i + hashed_subpacket_count
    (@parse_subpacket() while @slice.i < end)

  parse_subpacket : () ->
    len = @slice.read_v4_length()
    type = (@slice.read_uint8() & 0x7f)

  parse : () ->
    version = @slice.read_uint8()
    switch version
      when C.versions.signature.V3 then @parse_v3()
      when C.versions.signature.V4 then @parse_v4()


#===========================================================


