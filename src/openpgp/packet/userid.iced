
C = require('../../const').openpgp
triplesec = require 'triplesec'
{SHA1,SHA256} = triplesec.hash
{AES} = triplesec.ciphers
{native_rng} = triplesec.prng
{bufferify,uint_to_buffer} = require '../../util'
{encrypt} = require '../cfb'
{Packet} = require './base'

#=================================================================================

class UserID extends Packet

  # @param {Buffer} userid The utf8-buffer withstring reprensentation of the UserID
  constructor : (userid, @components = null) -> 
    @userid = bufferify userid
    @_parse() unless @compontents?
    super()

  #--------------------------

  utf8  : () -> @userid.toString('utf8')
  write : () -> @frame_packet C.packet_tags.userid, @userid

  #--------------------------

  @parse : (slice) -> new UserID slice.consume_rest_to_buffer() 

  #--------------------------

  to_userid : () -> @

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
    x = ///
      ^([^(<]*?)       # The beginning name of the user (no comment or key)
      \s+              # Separation before the key or comment
      (\((.*?)\)\s+)?  # The optional comment
      <(.*)?>$         # finally the key...
      ///
    if (m = @utf8().match x)?
      @components = 
        username : m[1]
        comment : m[3]
        email : m[4]

  #--------------------------

  get_username : () -> @components?.username
  get_comment  : () -> @components?.comment
  get_email    : () -> @components?.email

  #--------------------------

  @make : (components) ->
    comment = if (c = components.comment)? then "(#{c}) " else ""
    openpgp = "#{components.username} #{comment}<#{components.email}>"
    new UserId { openpgp, components }

#=================================================================================

exports.UserID = UserID

#=================================================================================
