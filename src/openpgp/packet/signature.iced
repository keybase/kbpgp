#
{Packet} = require './base'
C = require('../../const').openpgp
S = C.sig_subpacket
{encode_length,make_time_packet} = require '../util'
{unix_time,uint_to_buffer} = require '../../util'
{alloc_or_throw,SHA512,SHA1} = require '../../hash'
asymmetric = require '../../asymmetric'
util = require 'util'
packetsigs = require './packetsigs'
assert = require 'assert'
{SlicerBuffer} = require '../buffer'
{make_esc} = require 'iced-error'

#===========================================================

class Signature_v2_or_v3 extends Packet

  #---------------------

  constructor : ({ @key, @hasher, @key_id, @sig_data, @public_key_class,
                   @signed_hash_value_hash, @time, @sig, @type,
                   @version } ) ->
    @hasher = SHA512 unless @hasher?
    @_framed_output = null # sometimes we store the framed output here

  #---------------------

  is_signature : () -> true

  #---------------------

  get_key_id : () -> @key_id


  #---------------------

  # So this key behaves like a Sig V4
  get_key_flags : () -> 0
  get_key_expires : () -> 0

  #---------------------

  get_issuer_key_id : () -> @key_id

  #---------------------

  when_generated : () -> @time
  time_of_primary_uid_sig : () -> null

  #---------------------

  # For writing out these packets, which we'll likely never do.
  gen_prefix : () ->
    Buffer.concat [
      new Buffer [ C.versions.signature.V3, @type ],
      uint_to_buffer(32, @time),
      @key_id,
      new Buffer [ @key.type, @hasher.type ]
    ]

  #---------------------

  prepare_payload : (data_packets) ->
    bufs = (dp.to_signature_payload() for dp in data_packets)
    bufs.push(
      new Buffer([ @type ]),
      uint_to_buffer(32, @time)
    )
    Buffer.concat bufs

  #---------------------

  verify : (data_packets, cb) ->
    T = C.sig_types
    SKB = packetsigs.SubkeyBinding
    data_packets = [@primary].concat(data_packets) if (@type is T.subkey_binding)
    payload = @prepare_payload data_packets
    hash = @hasher payload
    s = new SlicerBuffer hash
    v = s.read_uint16()

    if (v isnt (b = @signed_hash_value_hash))
      err = new Error "quick hash check failed: #{v} != #{b}"
    else
      await @key.verify_unpad_and_check_hash { hash, @hasher, @sig }, defer err
      # If it's binary or text data, so that the packets have all be signed
      if err? then # noop
      else if @type in [ T.binary_doc, T.canonical_text ]
        for d in data_packets
          d.push_sig new packetsigs.Data { sig : @ }
      else if @type in [ T.subkey_binding ]
        for d in data_packets
          d.push_sig new SKB { @primary, sig : @, direction : SKB.DOWN }

    cb err

  #---------------------

#===========================================================

class Signature_v2 extends Signature_v2_or_v3

class Signature_v3 extends Signature_v2_or_v3

#===========================================================

class Signature extends Packet

  #---------------------

  constructor : ({ @key, @hasher, @key_id, @sig_data, @public_key_class,
                   @signed_hash_value_hash, @hashed_subpackets, @time, @sig, @type,
                   @unhashed_subpackets, @version } ) ->
    @hasher = SHA512 unless @hasher?
    @hashed_subpackets = [] unless @hashed_subpackets?
    @unhashed_subpackets = [] unless @unhashed_subpackets?
    @subpacket_index = @_make_subpacket_index()

    @_framed_output = null # sometimes we store the framed output here

  #---------------------

  get_key_id : () ->
    if @key_id then @key_id
    else @subpacket_index.all[S.issuer]?.id

  #---------------------

  _make_subpacket_index : () ->
    ret = { hashed : {}, unhashed : {}, all : {} }
    for p in @hashed_subpackets
      ret.hashed[p.type] = p
      ret.all[p.type] = p
    for p in @unhashed_subpackets
      ret.unhashed[p.type] = p
      ret.all[p.type] = p
    ret

  #---------------------

  prepare_payload : (data) ->
    flatsp = Buffer.concat( s.to_buffer() for s in @hashed_subpackets )

    prefix = Buffer.concat [
      new Buffer([ C.versions.signature.V4, @type, @key.type, @hasher.type ]),
      uint_to_buffer(16, flatsp.length),
      flatsp
    ]
    trailer = Buffer.concat [
      new Buffer([ C.versions.signature.V4, 0xff ]),
      uint_to_buffer(32, prefix.length)
    ]

    payload = Buffer.concat [ data, prefix, trailer ]
    hvalue = @hasher payload

    return { prefix, payload, hvalue }

  #---------------------

  # See write_message_signature in packet.signature.js
  write_unframed : (data, cb) ->
    esc = make_esc cb, "write_unframed"
    uhsp = Buffer.concat( s.to_buffer() for s in @unhashed_subpackets )

    { prefix, payload, hvalue } = @prepare_payload data
    await @key.pad_and_sign payload, { @hasher }, esc defer sig
    result2 = Buffer.concat [
      uint_to_buffer(16, uhsp.length),
      uhsp,
      new Buffer([hvalue.readUInt8(0), hvalue.readUInt8(1) ]),
      sig
    ]
    results = Buffer.concat [ prefix, result2 ]
    cb null, results

  #---------------------

  write : (data, cb) ->
    await @write_unframed data, defer err, unframed
    unless err?
      @_framed_output = ret = @frame_packet C.packet_tags.signature, unframed
    cb err, ret

  #-----------------

  # This is why we store the framed_output inside the packet after we write it
  # (see above in write).  Sometimes, in the case of public keys, we don't have the
  # capacity to regenerate signatures, so we just need to replay what we fetched.  But
  # other times, we want to rewrite the output. Through this mechanism we can handle both
  # cases.
  get_framed_output : () -> @_framed_output or @replay()

  #-----------------

  @parse : (slice) -> (new Parser slice).parse()

  #-----------------

  extract_key : (data_packets) ->
    for p in data_packets
      if p.key?
        @key = p.key
        break

  #-----------------

  verify : (data_packets, cb, opts) ->
    await @_verify data_packets, defer(err), opts
    for p in @unhashed_subpackets when (not err? and (s = p.to_sig())?)
      if s.type isnt C.sig_types.primary_binding
        err = new Error "unknown subpacket signature type: #{s.type}"
      else if data_packets.length isnt 1
        err = new Error "Needed 1 data packet for a primary_binding signature"
      else
        subkey = data_packets[0]
        s.primary = @primary
        s.key = subkey.key
        await s._verify [ subkey ], defer(err), opts
    cb err

  #-----------------

  _verify : (data_packets, cb, opts) ->
    err = null
    T = C.sig_types

    subkey = null

    # It's worth it to be careful here and check that we're getting the
    # right expected number of packets.
    @data_packets = switch @type
      when T.binary_doc, T.canonical_text then data_packets

      when T.issuer, T.persona, T.casual, T.positive, T.certificate_revocation

        if (n = data_packets.length) isnt 1
          err = new Error "Only expecting one UserID-style packet in a self-sig (got #{n})"
          []
        else
          # We need to use the primary key maybe several times,
          # so we unshift it onto the front of all sequences of data
          # packets.
          [ @primary ].concat data_packets

      when T.subkey_binding, T.primary_binding, T.subkey_revocation
        packets = []
        if data_packets.length isnt 1
          err =  new Error "Wrong number of data packets; expected only 1"
        else if not @primary?
          err = new Error "Need a primary key for subkey signature"
        else
          subkey = data_packets[0]
          packets = [ @primary, subkey ]
        packets

      when T.direct
        [ @primary].concat data_packets

      else
        err = new Error "cannot verify sigtype #{@type}"
        []

    # Now actually check that the signature worked.
    unless err?
      buffers = (dp.to_signature_payload() for dp in @data_packets)
      data = Buffer.concat buffers
      { payload, hvalue } = @prepare_payload data
      await @key.verify_unpad_and_check_hash { @sig, hash : hvalue, @hasher }, defer err

    # Check that our keys are not expired
    #
    # This is used to test if this (potential subkey) is expired as of the time
    # of the signature.  To use this feature, you have to enable 'time_travel' or specify 'now'
    # when you import the underlying pgp key in the first place. Otherwise the
    # subkey will simply fail to import (since it will assume 'unix_time()`).
    if not err? and @key_manager?
      err = @key_manager.pgp_check_not_expired { @subkey_material, now : opts?.now }

    # If we're signing a key, check key expiration now
    unless err?
      opts or= {}
      opts.subkey = subkey
      [err, key_expiration, sig_expiration] = @_check_key_sig_expiration opts
      opts.subkey = null

    # Now mark the object that was vouched for
    sig = @
    unless err?
      SKB = packetsigs.SubkeyBinding
      switch @type
        when T.binary_doc, T.canonical_text
          for d in @data_packets
            d.push_sig new packetsigs.Data { sig }

        when T.issuer, T.persona, T.casual, T.positive
          ps = null
          if (userid = @data_packets[1].to_userid())?
            ps = new packetsigs.SelfSig { @type, userid, sig }
            userid.push_sig ps
          else if (user_attribute = @data_packets[1].to_user_attribute())?
            ps = new packetsigs.SelfSig { @type, user_attribute, sig, key_expiration, sig_expiration }
            user_attribute.push_sig ps
          @primary.push_sig ps if ps

        when T.subkey_binding
          subkey.push_sig new SKB { @primary, sig, direction : SKB.DOWN, key_expiration, sig_expiration}

        when T.primary_binding
          subkey.push_sig new SKB { @primary, sig, direction : SKB.UP, key_expiration, sig_expiration}

        when T.subkey_revocation
          subkey.mark_revoked sig

    cb err

  #-----------------

  is_signature : () -> true

  #-----------------

  when_generated   : () -> @subpacket_index.hashed[S.creation_time]?.time
  get_key_expires : () -> @subpacket_index.hashed[S.key_expiration_time]?.time
  get_sig_expires : () -> @subpacket_index.hashed[S.expiration_time]?.time

  #-----------------

  time_primary_pair : () ->
    T = C.sig_types
    if @type in [ T.issuer, T.persona, T.casual, T.positive ]
      [ @when_generated(), !!(@subpacket_index.hashed[S.primary_user_id]?.flag) ]
    else
      null

  #-----------------

  # See Issue #28
  #   https://github.com/keybase/kbpgp/issues/28
  _check_key_sig_expiration : (opts) ->
    err = null
    T = C.sig_types
    key_expiration = 0
    sig_expiration = 0

    if @type in [ T.issuer, T.persona, T.casual, T.positive, T.subkey_binding, T.primary_binding ]

      key_creation = (opts.subkey or @primary).timestamp
      key_expiration_packet = @subpacket_index.hashed[S.key_expiration_time]
      sig_creation_packet = @subpacket_index.hashed[S.creation_time]
      sig_expiration_packet = @subpacket_index.hashed[S.sig_expiration_time]

      # We can set now back in time for some operations, like testing people's
      # old keys
      now = if (n = opts?.now)? then n else unix_time()

      if key_creation? and key_expiration_packet?.time
        key_expiration = key_creation + key_expiration_packet.time
      if sig_creation_packet? and sig_expiration_packet?.time
        sig_expiration = sig_creation_packet.time + sig_expiration_packet.time

      if key_expiration and not(opts.time_travel) and now > key_expiration
        err = new Error "Key expired #{now - key_expiration}s ago"
      if sig_expiration and not(opts.time_travel) and now > sig_expiration
        err = new Error "Sig expired #{now - key_expiration}s ago"

    return [err, key_expiration, sig_expiration]

  #-----------------

  get_key_flags : () ->
    @subpacket_index?.hashed?[C.sig_subpacket.key_flags]?.all_flags() or 0

  #-----------------

  get_issuer_key_id : () ->
    @subpacket_index?.all[C.sig_subpacket.issuer]?.id

#===========================================================

class SubPacket
  constructor : (@type) ->
    @critical = false
    @five_byte_len = false
  set_opts : (d) ->
    (@[k] = v for k,v of d)
    true
  to_buffer : () ->
    inner = @_v_to_buffer()
    Buffer.concat [
      encode_length(inner.length + 1, @five_byte_len),
      uint_to_buffer(8, (@type | (if @critical then 0x80 else 0x00))),
      inner
    ]
  to_sig : () -> null
  export_to_option : () -> null

#------------

# Ignore for the most part
class Experimental extends SubPacket
  constructor : (@buf, @type) ->
  @parse : (slice, type) ->
    new Experimental slice.consume_rest_to_buffer(), type
  _v_to_buffer : () -> @buf

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
    # No 'undefined' or null values allowed...
    for e in @v
      assert e?

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

class Exportable extends SubPacket
  constructor : (@flag) ->
    super S.exportable_certificate
  @parse : (slice) -> new Exportable slice.read_uint8()
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
    ret
  _v_to_buffer : () -> new Buffer @re, 'utf8'

#------------

class Revocable extends SubPacket
  constructor : (@flag) ->
    super S.revocable
  @parse : (slice) -> new Revocable slice.read_uint8()
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
    fp = slice.read_buffer SHA1.output_length
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
      new Buffer(@value)
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
  @parse : (slice) -> new PrimaryUserId slice.read_uint8()
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
  @parse : (slice) -> Preference.parse slice, KeyFlags
  all_flags : () ->
    ret = 0
    ret |= e for e in @v
    ret

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
    Buffer.concat [ uint_to_buffer(8, @flag), @reason ]

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
  constructor : ({@sig, @rawsig}) ->
    super S.embedded_signature
  _v_to_buffer : () -> @rawsig
  to_sig : () -> @sig
  @parse : (slice) ->
    rawsig = slice.peek_rest_to_buffer()
    sig = Signature.parse(slice)
    new EmbeddedSignature { sig, rawsig }

#===========================================================

exports.Signature = Signature

#===========================================================

class Parser

  constructor : (@slice) ->

  parse_v2_or_v3 : (v, klass) ->
    throw new error "Bad one-octet length" unless @slice.read_uint8() is 5
    o = {}
    o.type = @slice.read_uint8()
    o.time = @slice.read_uint32()
    o.sig_data = @slice.peek_rest_to_buffer()
    o.key_id = @slice.read_buffer 8
    o.public_key_class = asymmetric.get_class @slice.read_uint8()
    o.hasher = alloc_or_throw @slice.read_uint8()
    o.signed_hash_value_hash = @slice.read_uint16()
    o.sig = o.public_key_class.parse_sig @slice
    o.version = v
    new klass o

  parse_v4 : () ->
    o = {}
    o.type = @slice.read_uint8()
    o.public_key_class = asymmetric.get_class @slice.read_uint8()
    o.hasher = alloc_or_throw @slice.read_uint8()
    hashed_subpacket_count = @slice.read_uint16()
    end = @slice.i + hashed_subpacket_count
    o.sig_data = @slice.peek_to_buffer hashed_subpacket_count
    o.hashed_subpackets = (@parse_subpacket() while @slice.i < end)
    unhashed_subpacket_count = @slice.read_uint16()
    end = @slice.i + unhashed_subpacket_count
    o.unhashed_subpackets = (@parse_subpacket() while @slice.i < end)
    o.signed_hash_value_hash = @slice.read_uint16()
    o.sig = o.public_key_class.parse_sig @slice
    o.version = 4
    new Signature o

  parse_subpacket : () ->
    [len, five_byte_len] = @slice.read_v4_length()
    raw_type = @slice.read_uint8()
    type = (raw_type & 0x7f)
    critical = !!(raw_type & 0x80)
    # (len - 1) since we don't want the packet tag to count toward the len
    end = @slice.clamp (len - 1)
    klass = switch type
      when S.creation_time then CreationTime
      when S.expiration_time then ExpirationTime
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
      else
        if type >= S.experimental_low and type <= S.experimental_high then Experimental
        else throw new Error "Unknown signature subpacket: #{type}"
    ret = klass.parse @slice, type
    ret.set_opts { critical, five_byte_len }
    @slice.unclamp end
    ret

  parse : () ->
    version = @slice.read_uint8()
    switch version
      when C.versions.signature.V2 then @parse_v2_or_v3 version, Signature_v2
      when C.versions.signature.V3 then @parse_v2_or_v3 version, Signature_v3
      when C.versions.signature.V4 then @parse_v4()
      else throw new Error "Unknown signature version: #{version}"

#===========================================================

exports.CreationTime = CreationTime
exports.KeyFlags = KeyFlags
exports.KeyExpirationTime = KeyExpirationTime
exports.PreferredSymmetricAlgorithms = PreferredSymmetricAlgorithms
exports.PreferredHashAlgorithms = PreferredHashAlgorithms
exports.PreferredCompressionAlgorithms = PreferredCompressionAlgorithms
exports.Features = Features
exports.KeyServerPreferences = KeyServerPreferences
exports.Issuer = Issuer
exports.EmbeddedSignature = EmbeddedSignature
exports.PrimaryUserId = PrimaryUserId

#===========================================================


