
{InitTransform} = require 'iced-stream'
util = require '../util'

#==================================================================================================
#
# If we're streaming data and we don't know ahead of time how big it is, 
# we can packetize via this class.  It obeys the standard Node.js stream
# interface.  It will buffer until it has 2^(log2_chunksz) bytes ready,
# and write out that chunk.  Of course we need to be certain to flush it
# at the end, which will write out a final packet size.
# 
exports.PacketizerStream = class Transform extends InitTransform

  constructor : ({tag, log2_chunksz, header, packet}) ->
    log2_chunksz or= 16
    @_chunksz = (1 << log2_chunksz)
    @_prefix = new Buffer [(0xe0 | log2_chunksz)] # AKA 224 + log2_chunksz
    @_buffers = []
    @_packet = packet # on OpenPGP packet that might contain a tag
    @_tag = tag or packet?.TAG
    @_dlen = 0
    @_push_to_buffer header
    super()

  _push_to_buffer : (b) ->
    @_buffers.push b
    @_dlen += b.length

  _do_tag : () ->
    if @_tag
      @push new Buffer [@_tag]
      @_tag = null

  _v_init : (cb) ->
    @_do_tag()
    err = null
    if @_packet?
      await @_packet.write_unframed defer err, buf
      @_push_to_buffer buf unless err?
    cb err

  _v_transform : (buf, encoding, cb) ->
    @_push_to_buffer buf
    if @_dlen >= @_chunksz
      flat = Buffer.concat @_buffers
      pos = 0
      while (end = pos + @_chunksz) <= @_dlen
        @push @_prefix
        @push flat[pos...end]
        pos = end
      rest = flat[pos...]
      @_buffers = [ rest ]
      @_dlen = rest.length
    cb()

  _v_flush : (cb) ->
    if @dlen > 0
      buf = Buffer.concat @_buffers
      @_buffers = []
      @push util.encode_length(@_dlen)
      @push buf 
      @_dlen = 0
    cb()

#==================================================================================================

# a small tester function
test = () ->
  buf = Buffer.concat (new Buffer([32...61]) for [0...16])
  x = new Transform  { log2_chunksz : 5, tag : 0x33, header : new Buffer("hello") }
  x.pipe process.stdout
  x.on 'end', () -> console.error "ok done!"
  await x.write buf, defer()
  await x.end defer()
