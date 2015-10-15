
C = require('../../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{bufferify,uint_to_buffer} = require '../../util'
{encrypt} = require '../cfb'
{Packet} = require './base'
{parse} = require('pgp-utils').userid

#=================================================================================

class UserID extends Packet

  # @param {Buffer} userid The utf8-buffer withstring reprensentation of the UserID
  constructor : (userid, @components = null) ->
    @userid = bufferify userid
    @_parse() unless @compontents?
    super()
    @_time_primary_pair = null
    @primary = false
    @most_recent_sig = null

  #--------------------------

  utf8  : () -> @userid.toString('utf8')
  write : () -> @frame_packet C.packet_tags.userid, @userid

  #--------------------------

  @parse : (slice) -> new UserID slice.consume_rest_to_buffer()

  #--------------------------

  to_userid : () -> @

  #--------------------------

  cmp : (b) ->
    x = @utf8()
    y = b.utf8()
    if x < y then -1 else if x is y then 0 else 1

  #--------------------------

  to_signature_payload : () ->

    # RFC 4880 5.2.4 Computing Signatures Over a Key
    Buffer.concat [
      new Buffer([ C.signatures.userid ]),
      uint_to_buffer(32, @userid.length),
      @userid
    ]

  #--------------------------

  _parse : () ->
    @components = c if (c = parse @utf8())?

  #--------------------------

  get_username : () -> @components?.username
  get_comment  : () -> @components?.comment
  get_email    : () -> @components?.email

  #--------------------------

  # Return a [t0, t1] pair, where both are Unix timestamps.  t0 is the
  # most recent self-signature of this UID. t1 is the most recent self-signature
  # of this UID that claims that it's the primary UID.
  time_primary_pair : () ->
    unless @_time_primary_pair?
      pairs = (s?.sig?.time_primary_pair() for s in @get_psc().get_self_sigs())
      max = null
      ret = [ null, null ]
      for p in pairs when p?
        if p[0] and ((not ret[0]?) or (ret[0] < p[0])) then ret[0] = p[0]
        if p[1] and ((not ret[1]?) or (ret[1] < p[0])) then ret[1] = p[0]
      @_time_primary_pair = ret
      @most_recent_sig = ret[0]
    return @_time_primary_pair

  #--------------------------

  @make : (components) ->
    comment = if (c = components.comment)? then "(#{c}) " else ""
    userid = "#{components.username} #{comment}<#{components.email}>"
    new UserID userid, components

  #--------------------------

  get_framed_signature_output : () ->
    @get_psc()?.get_self_sig()?.sig?.get_framed_output()

#=================================================================================

exports.UserID = UserID

#=================================================================================
