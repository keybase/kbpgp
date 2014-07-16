
xbt = require '../../xbt'
util = require '../util'

#==================================================================================================
#
# If we're streaming data and we don't know ahead of time how big it is, 
# we can packetize via this class.  It obeys the standard Node.js stream
# interface.  It will buffer until it has 2^(log2_chunksz) bytes ready,
# and write out that chunk.  Of course we need to be certain to flush it
# at the end, which will write out a final packet size.
# 
exports.Packetizer = class Packetizer extends xbt.SimpleInit

  constructor : ({tag, log2_chunksz, header, packet}) ->
    log2_chunksz or= 16
    @_chunksz = (1 << log2_chunksz)
    @_prefix = new Buffer [(0xe0 | log2_chunksz)] # AKA 224 + log2_chunksz
    @_buffers = []
    @_packet = packet # on OpenPGP packet that might contain a tag
    @_tag = tag or packet?.TAG
    @_dlen = 0
    @_push_to_buffer header if header?
    super()

  _push_to_buffer : (b) ->
    if b? and b.length
      @_buffers.push b
      @_dlen += b.length

  _v_init : (cb) ->
    err = ret = null
    if @_tag then ret = new Buffer [ @_tag ]
    if @_packet?
      await @_packet.write_unframed defer err, buf
      @_push_to_buffer buf unless err?
    cb err, ret

  _v_chunk : ({data, eof}, cb) ->
    bufs = []
    @_handle_data(data, bufs) if data?
    @_handle_flush(bufs)      if eof
    cb null, Buffer.concat(bufs)

  _handle_data : (data, bufs) ->
    @_push_to_buffer data
    if @_dlen >= @_chunksz
      flat = Buffer.concat @_buffers
      pos = 0
      while (end = pos + @_chunksz) <= @_dlen
        bufs.push @_prefix
        bufs.push flat[pos...end]
        pos = end
      rest = flat[pos...]
      @_buffers = [ rest ]
      @_dlen = rest.length

  _handle_flush : (bufs) ->
    if @dlen > 0
      buf = Buffer.concat @_buffers
      @_buffers = []
      bufs.push util.encode_length buf.length
      bufs.push buf 
      @_dlen = 0

#==================================================================================================

# a small tester function
test = () ->
  buf = Buffer.concat (new Buffer([32...61]) for [0...16])
  x = new Transform  { log2_chunksz : 5, tag : 0x33, header : new Buffer("hello") }
  x.pipe process.stdout
  x.on 'end', () -> console.error "ok done!"
  await x.write buf, defer()
  await x.end defer()
