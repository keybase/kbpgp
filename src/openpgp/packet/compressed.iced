
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
zlib = require 'zlib'
{uint_to_buffer} = require '../../util'
compressjs = require 'keybase-compressjs'
{Packetizer} = require './xbt_packetizer'
{Chain,ReverseAdapter} = require '../../xbt'
{make_esc} = require 'iced-error'
{PacketParser} = require './xbt_depacketizer'

#=================================================================================

fake_zip_inflate = (buf, cb) ->
  buf = Buffer.concat [ new Buffer([0x78,0x9c]), buf ]
  await zlib.inflate buf, defer err, ret
  cb err, ret

fake_zip_deflate = (buf, cb) ->
  await zlib.deflate buf, defer err, ret
  ret = ret[3...] if not(err?) and ret?
  cb err, ret

bzip_inflate = (buf, cb) ->
  err = null
  try
    ret = compressjs.Bzip2.decompressFile(buf)
    ret = new Buffer(ret) if ret?
  catch e
    err = e
  cb err, ret

#=================================================================================

# 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
class Compressed extends Packet

  @TAG : C.packet_tags.compressed
  TAG : Compressed.TAG

  #--------

  constructor : ( {@algo, @compressed, @inflated}) ->

  #--------

  @parse : (slice) -> (new CompressionParser slice).parse()

  #--------

  inflate : (cb) ->
    err = ret = null
    switch @algo
      when C.compression.none then ret = @compressed
      when C.compression.zlib
        await zlib.inflate @compressed, defer err, ret
      when C.compression.zip
        await fake_zip_inflate @compressed, defer err, ret
      when C.compression.bzip
        await bzip_inflate @compressed, defer err, ret
      else
        err = new Error "no known inflation -- algo: #{@algo}"
    cb err, ret

  #--------

  deflate : (cb) ->
    err = ret = null
    switch @algo
      when C.compression.none then ret = @inflated
      when C.compression.zlib
        await zlib.deflate @inflated, defer err, ret
      when C.compression.zip
        await fake_zip_deflate @inflated, defer err, ret
      else
        err = new Error "no known deflation -- algo: #{@algo}"
    cb err, ret

  #--------

  write_unframed : (cb) ->
    err = ret = null
    bufs = [ uint_to_buffer(8, @algo) ]
    if @inflated?
      await @deflate defer err, @compressed
      bufs.push @compressed
    ret = Buffer.concat bufs
    cb err, ret

  #--------

  new_xbt : () -> new XbtOut { packet : @ }
  @new_xbt_parser : (arg) -> new XbtIn arg

#=================================================================================

class CompressionParser 

  constructor : (@slice) ->

  #  The body of this packet consists of:
  #
  #   - A one-octet version number.  The only currently defined value is 1.
  #   - Encrypted data, the output of the selected symmetric-key cipher
  #     operating in Cipher Feedback mode with shift amount equal to the
  #     block size of the cipher (CFB-n where n is the block size).
  parse : () ->
    algo = @slice.read_uint8()
    compressed = @slice.consume_rest_to_buffer()
    new Compressed { algo, compressed }

#=================================================================================

exports.XbtOut = class XbtOut extends Packetizer

  _v_init : (cb) ->
    await super defer err, data
    err = @_setup_stream() unless err?
    cb err, data

  _setup_stream : () ->
    @_stream = switch @packet().algo
      when C.compression.zlib then new ReverseAdapter { stream : zlib.createDeflate() }
      else
        err = new Error "unhandled streaming compression algorithm: #{@packet.algo}"
        null
    return err

  _v_chunk : ({data, eof}, cb) -> 
    esc = make_esc cb, "compresed.XbtOut._v_chunk"
    await @_stream.chunk { data, eof }, esc defer data
    super { data, eof }, cb

#=================================================================================

class XbtIn extends PacketParser

  #----------------------

  constructor : (arg) -> 
    super arg
    @_inflate_stream = zlib.createInflate()

  #----------------------

  _parse_header : (cb) ->
    err = null
    esc = make_esc cb, "_parse_header"
    await @_read_uint8 esc defer algo
    @_inflate_stream = switch algo
      when C.compression.zlib then zlib.createInflate()
      else
        err = new Error "unhandled streaming inflation algorithn: #{algo}" 
    cb err

  #----------------------

  _run_body : (cb) ->
    inflate_xbt = new ReverseAdapter { stream : @_inflate_stream }
    demux_xbt = new @substream_klass {}
    chain = new Chain [ inflate_xbt, demux_xbt ]
    await @_stream_to chain, defer err
    cb err

#=================================================================================

exports.Compressed = Compressed

#=================================================================================
