
{Packet} = require './base'
C = require('../const').openpgp
{uint_to_buffer,encode_length,make_time_packet} = require '../util'
{alloc_or_throw,SHA512,SHA1} = require '../hash'
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

class SubPacket 

#------------

class ExpirationTime extends SubPacket
  constructor : (@time) -> @never_expires = (@time is 0)
  @parse : (slice, klass) -> new klass slice.read_uint32()

#------------

class Preference extends SubPacket
  constructor : (@v) ->
  @parse : (slice, klass) -> 
    v = (c for c in slice.consume_rest_to_buffer())
    new klass v

#------------

class SigCreationTime extends SubPacket
  constructor : (@time) ->
  @parse : (slice) -> 
    ret = new SigCreationTime new Date (slice.read_uint32() * 1000)
    console.log ret.time
    ret

#------------

class SigExpirationTime extends ExpirationTime
  @parse : (slice) -> ExpirationTime.parse slice, SigExpirationTime

#------------

class Exporatable extends SubPacket
  constructor : (@flag) ->
  @parse : (slice) -> new Exporatable (slice.read_uint8() is 1)

#------------

class Trust extends SubPacket
  constructor : (@level, @amount) ->
  @parse : (slice) -> new Trust slice.read_uint8(), slice.read_uint8()

#------------

class RegularExpression extends SubPacket
  constructor : (@re) ->
  @parse : (slice) -> 
    ret = new RegularExpression slice.consume_rest_to_buffer().toString 'utf8'
    console.log ret.re
    ret

#------------

class Revocable extends SubPacket
  constructor : (@flag) ->
  @parse : (slice) -> new Revocable (slice.read_uint8() is 1)

#------------

class KeyExpirationTime extends ExpirationTime
  @parse : (slice) -> ExpirationTime.parse slice, KeyExpirationTime

#------------

class PreferredSymmetricAlgorithms extends Preference
  @parse : (slice) -> Preference.parse slice, PreferredSymmetricAlgorithms

#------------

class RevocationKey extends SubPacket
  constructor : (@key_class, @alg, @fingerprint) ->
  @parse : (slice) ->
    kc = slice.read_uint8()
    ka = slice.read_uint8()
    fp = slice.read_buffer SHA1.output_size
    return new RevocationKey kc, ka, fp

#------------

class Issuer extends SubPacket
  constructor : (@id) ->
  @parse : (slice) -> new Issuer slice.read_buffer 8

#------------

class NotationData extends SubPacket
  constructor : (@flags, @name, @value) ->
  @parse : (slice) -> 
    flags = slice.read_uint32()
    nl = slice.read_uint16()
    vl = slice.read_uint16()
    name = slice.read_buffer nl
    value = slice.read_buffer vl
    new NotationData flags, name, value

#------------

class PreferredHashAlgorithms extends Preference
  @parse : (slice) -> Preference.parse slice, PreferredHashAlgorithms

#------------

class PreferredCompressionAlgorithms extends Preference
  @parse : (slice) -> Preference.parse slice, PreferredCompressionAlgorithms

#------------

class KeyServerPreferences extends Preference
  @parse : (slice) -> Preference.parse slice, PreferredKeyServer

#------------

class PreferredKeyServer extends SubPacket
  constructor : (@server) ->
  @parse : (slice) -> new PreferredKeyServer slice.consume_rest_to_buffer()

#------------

class PrimaryUserId extends SubPacket
  constructor : (@flag) ->
  @parse : (slice) -> new PrimaryUserId (slice.read_uint8() is 1)

#------------

class PolicyURI extends SubPacket
  constructor : (@flag) ->
  @parse : (slice) -> new PolicyURI slice.consume_rest_to_buffer()

#------------

class KeyFlags extends Preference
  @parse : (slice) -> Preference.parse slice, KeyFlags

#------------

class SignersUserID extends SubPacket
  constructor : (@uid) ->
  @parse : (slice) -> new SignersUserID slice.consume_rest_to_buffer()

#------------

class ReasonForRevocation extends SubPacket
  constructor : (@flag, @reason) ->
  @parse : (slice) ->
    flag = slice.read_uint8()
    reason = slice.consume_rest_to_buffer()
    return new ReasonForRevocation flag, reason

#------------

class Features extends SubPacket
  @parse : (slice) -> throw new Error "unimplemented!"

#------------

class SignatureTarget extends SubPacket
  constructor : (@pub_key_alg, @hasher, @hval) ->
  @parse : (slice) ->
    pka = slice.read_uint8()
    hasher = alloc_or_throw slice.read_uint8()
    hval = slice.read_buffer ha.output_length
    new SignatureTarget pka, hasher, hval

#------------

class EmbeddedSignature extends SubPacket
  constructor : (@sig) ->
  @parse : (slice) -> new EmbeddedSignature Signature.parse slice

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
    @sig_data = @slice.peek_to_buffer end
    end = @slice.i + hashed_subpacket_count
    @subpackets = (@parse_subpacket() while @slice.i < end)
    @signed_hash_value_hash = @slice.read_uint16()
    @sig = @public_key_class.parse_sig @slice

  parse_subpacket : () ->
    len = @slice.read_v4_length()
    type = (@slice.read_uint8() & 0x7f)
    S = C.sig_subpacket
    # (len - 1) since we don't want the packet tag to count toward the len
    end = @slice.clamp (len - 1)
    klass = switch type
      when S.creation_time then SigCreationTime
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
    console.log "subpacket type -> #{type} #{len}"
    ret

  parse : () ->
    version = @slice.read_uint8()
    switch version
      when C.versions.signature.V3 then @parse_v3()
      when C.versions.signature.V4 then @parse_v4()
      else throw new Error "Unknown signature version: #{version}"

#===========================================================


 