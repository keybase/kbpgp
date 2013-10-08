
{Packet} = require './base'
C = require('../const').openpgp
S = C.sig_subpacket
{uint_to_buffer,encode_length,make_time_packet} = require '../util'
{alloc_or_throw,SHA512,SHA1} = require '../hash'
asymmetric = require '../asymmetric'

#===========================================================

class Signature extends Packet

  #---------------------

  constructor : ({ @key, @hasher, @key_id, @sig_data, @public_key_class, 
                   @signed_hash_value_hash, @hashed_subpackets, @time, @sig, @type,
                   @unhashed_subpackets } ) ->
    @hasher = SHA512 unless @hasher?
    @hashed_subpackets = [] unless @hashed_subpackets?
    @unhashed_subpackets = [] unless @unhashed_subpackets?

  #---------------------

  prepare_payload : (data) -> 
    flatsp = Buffer.concat( s.to_buffer() for s in @hashed_subpackets )

    prefix = Buffer.concat [ 
      new Buffer([ C.versions.signature.V4, @type, @key.type, @hasher.type ]),
      uint_to_buffer(16, flatsp.length),
      flatsp
    ]
    console.log "prepare payload ->"
    console.log flatsp.toString('hex')

    trailer = Buffer.concat [
      new Buffer([ C.versions.signature.V4, 0xff ]),
      uint_to_buffer(32, prefix.length)
    ]

    payload = Buffer.concat [ data, prefix, trailer ]
    hvalue = @hasher payload

    return { prefix, payload, hvalue }

  #---------------------

  # See write_message_signature in packet.signature.js
  write : (data, cb) ->

    { prefix, payload, hvalue } = @prepare_payload data
    sig = @key.pad_and_sign payload, { @hasher }
    result2 = Buffer.concat [
      uint_to_buffer(16, 0), # 0 unhashed packets, so write a 0!
      new Buffer([hvalue.readUInt8(0), hvalue.readUInt8(1) ]),
      sig
    ]
    results = Buffer.concat [ prefix, result2 ]
    ret = @frame_packet(C.packet_tags.signature, results)
    cb null, ret

  #-----------------
  
  @parse : (slice) -> (new Parser slice).parse()

  #-----------------

  extract_key : (data_packets) ->
    for p in data_packets
      if p.key?
        @key = p.key
        break

  #-----------------

  verify : (data_packets, cb) ->
    data = Buffer.concat (dp.to_signature_payload() for dp in data_packets)
    { payload } = @prepare_payload data
    err = @key.verify_unpad_and_check_hash @sig, payload, @hasher
    cb err

  #-----------------

  is_signature : () -> true
 
#===========================================================

class SubPacket
  constructor : (@type) ->
  to_buffer : () ->
    inner = @_v_to_buffer()
    Buffer.concat [
      encode_length(inner.length + 1),
      uint_to_buffer(8, @type),
      inner
    ]

#------------

class Time extends SubPacket
  constructor : (type, @time) ->
    @never_expires = (@time is 0)
    super type
  @parse : (slice, klass) -> new klass slice.read_uint32()
  _v_to_buffer : () -> uint_to_buffer 32, @time

#------------

class Preference extends SubPacket
  constructor : (type, @v) -> 
    super type
  @parse : (slice, klass) -> 
    v = (c for c in slice.consume_rest_to_buffer())
    new klass v
  _v_to_buffer : () -> new Buffer (e for e in @v)

#------------

class CreationTime extends Time
  constructor : (t) ->
    super S.creation_time, t
  @parse : (slice) -> Time.parse slice, CreationTime

#------------

class ExpirationTime extends Time
  constructor : (t) ->
    super S.expiration_time, t
  @parse : (slice) -> Time.parse slice, ExpirationTime

#------------

class Exporatable extends SubPacket
  constructor : (@flag) ->
    super S.exportable_certificate
  @parse : (slice) -> new Exporatable (slice.read_uint8() is 1)
  _v_to_buffer : () -> uint_to_buffer 8, @flag

#------------

class Trust extends SubPacket
  constructor : (@level, @amount) ->
    super S.trust_signature
  @parse : (slice) -> new Trust slice.read_uint8(), slice.read_uint8()
  _v_to_buffer : () -> 
    Buffer.concat [
      uint_to_buffer(8, @level),
      uint_to_buffer(8, @amount),
    ]

#------------

class RegularExpression extends SubPacket
  constructor : (@re) ->
    super S.regular_expression
  @parse : (slice) -> 
    ret = new RegularExpression slice.consume_rest_to_buffer().toString 'utf8'
    console.log ret.re
    ret
  _v_to_buffer : () -> new Buffer @re, 'utf8'

#------------

class Revocable extends SubPacket
  constructor : (@flag) ->
    super S.revocable
  @parse : (slice) -> new Revocable (slice.read_uint8() is 1)
  _v_to_buffer : () -> uint_to_buffer 8, @flag

#------------

class KeyExpirationTime extends Time
  constructor : (t) ->
    super S.key_expiration_time, t
  @parse : (slice) -> Time.parse slice, KeyExpirationTime

#------------

class PreferredSymmetricAlgorithms extends Preference
  constructor : (v) ->
    super S.preferred_symmetric_algorithms, v
  @parse : (slice) -> Preference.parse slice, PreferredSymmetricAlgorithms

#------------

class RevocationKey extends SubPacket
  constructor : (@key_class, @alg, @fingerprint) ->
    super S.revocation_key
  @parse : (slice) ->
    kc = slice.read_uint8()
    ka = slice.read_uint8()
    fp = slice.read_buffer SHA1.output_size
    return new RevocationKey kc, ka, fp
  _v_to_buffer : () ->
    Buffer.concat [
      uint_to_buffer(8, @key_class),
      uint_to_buffer(8, @alg),
      new Buffer(@fingerprint)
    ]

#------------

class Issuer extends SubPacket
  constructor : (@id) ->
    super S.issuer
  @parse : (slice) -> new Issuer slice.read_buffer 8
  _v_to_buffer : () -> new Buffer @id

#------------

class NotationData extends SubPacket
  constructor : (@flags, @name, @value) ->
    super S.notation_data
  @parse : (slice) -> 
    flags = slice.read_uint32()
    nl = slice.read_uint16()
    vl = slice.read_uint16()
    name = slice.read_buffer nl
    value = slice.read_buffer vl
    new NotationData flags, name, value
  _v_to_buffer : () ->
    Buffer.concat [
      uint_to_buffer(32, @flags),
      uint_to_buffer(16, @name.length),
      uint_to_buffer(16, @value.length),
      new Buffer(@name),
      new Buffer(@valeue)
    ]

#------------

class PreferredHashAlgorithms extends Preference
  constructor : (v) ->
    super S.preferred_hash_algorithms, v
  @parse : (slice) -> Preference.parse slice, PreferredHashAlgorithms

#------------

class PreferredCompressionAlgorithms extends Preference
  constructor : (v) ->
    super S.preferred_compression_algorithms, v
  @parse : (slice) -> Preference.parse slice, PreferredCompressionAlgorithms

#------------

class KeyServerPreferences extends Preference
  constructor : (v) ->
    super S.key_server_preferences, v
  @parse : (slice) -> Preference.parse slice, KeyServerPreferences

#------------

class Features extends Preference
  constructor : (v) ->
    super S.features, v
  @parse : (slice) -> Preference.parse slice, Features

#------------

class PreferredKeyServer extends SubPacket
  constructor : (@server) ->
    super S.preferred_key_server
  @parse : (slice) -> new PreferredKeyServer slice.consume_rest_to_buffer()
  _v_to_buffer : () -> @server

#------------

class PrimaryUserId extends SubPacket
  constructor : (@flag) ->
    super S.primary_user_id
  @parse : (slice) -> new PrimaryUserId (slice.read_uint8() is 1)
  _v_to_buffer : () -> uint_to_buffer(8, @flag)

#------------

class PolicyURI extends SubPacket
  constructor : (@flag) ->
    super S.policy_uri
  @parse : (slice) -> new PolicyURI slice.consume_rest_to_buffer()
  _v_to_buffer : () -> @flag

#------------

class KeyFlags extends Preference
  constructor : (v) ->
    super S.key_flags, v
    console.log "key flags -> #{v}"
  @parse : (slice) -> Preference.parse slice, KeyFlags

#------------

class SignersUserID extends SubPacket
  constructor : (@uid) ->
    super S.signers_user_id
  @parse : (slice) -> new SignersUserID slice.consume_rest_to_buffer()
  _v_to_buffer : () -> @uid

#------------

class ReasonForRevocation extends SubPacket
  constructor : (@flag, @reason) ->
    super S.reason_for_revocation
  @parse : (slice) ->
    flag = slice.read_uint8()
    reason = slice.consume_rest_to_buffer()
    return new ReasonForRevocation flag, reason
  _v_to_buffer : () ->
    Buffet.concat [ uint_to_buffer(8, @flag), @reason ]

#------------

class SignatureTarget extends SubPacket
  constructor : (@pub_key_alg, @hasher, @hval) ->
    super S.signature_target
  @parse : (slice) ->
    pka = slice.read_uint8()
    hasher = alloc_or_throw slice.read_uint8()
    hval = slice.read_buffer hasher.output_length
    new SignatureTarget pka, hasher, hval
  _v_to_buffer : () ->
    Buffer.concat [
      uint_to_buffer(8, @pub_key_alg),
      uint_to_buffer(8, @hasher.type),
      @hval
    ]

#------------

class EmbeddedSignature extends SubPacket
  constructor : (@sig) ->
    super S.embedded_signature
  @parse : (slice) -> new EmbeddedSignature Signature.parse slice

#===========================================================

exports.Signature = Signature

#===========================================================

class Parser

  constructor : (@slice) ->

  parse_v3 : () ->
    throw new error "Bad one-octet length" unless @slice.read_uint8() is 5
    o = {}
    o.type = @slice.read_uint8()
    o.time = new Date (@slice.read_uint32() * 1000)
    o.sig_data = @slice.peek_rest_to_buffer()
    o.key_id = @slice.read_buffer 8
    o.public_key_class = asymmetric.get_class @slice.read_uint8()
    o.hash = alloc_or_throw @slice.read_uint8()
    o.signed_hash_value_hash = @slice.read_uint16()
    o.sig = @public_key_class.parse_sig @slice
    new Signature o

  parse_v4 : () ->
    o = {}
    o.type = @slice.read_uint8()
    o.public_key_class = asymmetric.get_class @slice.read_uint8()
    o.hasher = alloc_or_throw @slice.read_uint8()
    hashed_subpacket_count = @slice.read_uint16()
    end = @slice.i + hashed_subpacket_count
    o.sig_data = @slice.peek_to_buffer hashed_subpacket_count
    console.log o.sig_data.toString 'hex'
    o.hashed_subpackets = (@parse_subpacket() while @slice.i < end)
    unhashed_subpacket_count = @slice.read_uint16()
    end = @slice.i + unhashed_subpacket_count
    o.unhashed_subpackets = (@parse_subpacket() while @slice.i < end)
    o.signed_hash_value_hash = @slice.read_uint16()
    o.sig = o.public_key_class.parse_sig @slice
    new Signature o

  parse_subpacket : () ->
    len = @slice.read_v4_length()
    type = (@slice.read_uint8() & 0x7f)
    # (len - 1) since we don't want the packet tag to count toward the len
    end = @slice.clamp (len - 1)
    klass = switch type
      when S.creation_time then CreationTime
      when S.expiration_time then SigExpirationTime
      when S.exportable_certificate then Exportable
      when S.trust_signature then Trust
      when S.regular_expression then RegularExpression
      when S.revocable then Revocable
      when S.key_expiration_time then KeyExpirationTime
      when S.preferred_symmetric_algorithms then PreferredSymmetricAlgorithms
      when S.revocation_key then RevocationKey
      when S.issuer then Issuer
      when S.notation_data then NotationData
      when S.preferred_hash_algorithms  then PreferredHashAlgorithms
      when S.preferred_compression_algorithms then PreferredCompressionAlgorithms
      when S.key_server_preferences then KeyServerPreferences
      when S.preferred_key_server then PreferredKeyServer
      when S.primary_user_id then PrimaryUserId
      when S.policy_uri then PolicyURI
      when S.key_flags then KeyFlags
      when S.signers_user_id then SignersUserID
      when S.reason_for_revocation then ReasonForRevocation
      when S.features then Features
      when S.signature_target then SignatureTarget
      when S.embedded_signature then EmbeddedSignature
      else throw new Error "Unknown signature subpacket: #{type}"
    ret = klass.parse @slice
    @slice.unclamp end
    ret

  parse : () ->
    version = @slice.read_uint8()
    switch version
      when C.versions.signature.V3 then @parse_v3()
      when C.versions.signature.V4 then @parse_v4()
      else throw new Error "Unknown signature version: #{version}"

#===========================================================

exports.CreationTime = CreationTime
exports.Issuer = Issuer

#===========================================================

 