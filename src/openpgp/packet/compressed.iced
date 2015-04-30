
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
zlib = require 'zlib'
{uint_to_buffer} = require '../../util'
bzipDeflate = require 'bzip-deflate'

#=================================================================================

#
# Workaround browserify bug, not in use, see note right below.
#
#fake_zip_inflate = (buf, cb) ->
#  pako = require 'pako'
#  buf = Buffer.concat [ new Buffer([0x78,0x9c]), buf ]
#  ret = null
#  try
#    ret = new Buffer pako.inflate buf
#  catch e
#    err = e
#  cb err, ret

# Address keybase/keybase-issues#921.
#
# I didn't track it all the way down, but there's an issue with browserify-zlib decrypting
# our fake ZIP archives.  When the "flush" is sent with 0 in bytes, it returns a Z_BUF_ERROR,
# as if it still wants more data.  I think it's safe to ignore this error, but we should recheck
# this assumption.  If we turn out to be wrong, we might need to call into pako directly
# as shown above.  Calling into pako directly has problems, though, since it will be included
# in the node.js setting which will increase code bloat.
#
fake_zip_inflate = (buf, cb) ->
  buf = Buffer.concat [ new Buffer([0x78,0x9c]), buf ]
  inflater = zlib.createInflate { flush : zlib.Z_FULL_FLUSH }
  bufs = []

  call_end = (err) ->
    if (tmp = cb)?
      # This actually isn't an error, so we're OK to ignore it... I think....
      if err? and err.code is "Z_BUF_ERROR" then err = null
      cb = null
      if err? then ret = null else ret = Buffer.concat(bufs)
      tmp err, ret

  inflater.on 'readable', () ->
    read_buf = inflater.read()
    bufs.push read_buf if read_buf?
  inflater.on 'end', () ->
    call_end null
  inflater.on 'error', (e) ->
    call_end e

  await inflater.write buf, defer err
  unless err?
    await inflater.end err
  if err?
    call_end err

#-----------------

fix_zip_deflate = (buf, cb) ->
  await zlib.deflate buf, defer err, ret
  cb err, ret

#-----------------

bzip_inflate = (buf, cb) ->
  err = null
  try
    ret = bzipDeflate buf
  catch e
    err = e
  cb err, ret

#=================================================================================

# 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
class Compressed extends Packet

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
    await @deflate defer err, @compressed
    unless err?
      bufs = [ uint_to_buffer(8, @algo), @compressed ]
      ret = Buffer.concat bufs
    cb err, ret

  #--------

  write : (cb) ->
    err = ret = null
    await @write_unframed defer err, unframed
    unless err?
      ret = @frame_packet C.packet_tags.compressed, unframed
    cb err, ret

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

exports.Compressed = Compressed

#=================================================================================
