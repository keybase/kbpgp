
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
zlib = require 'zlib'
{uint_to_buffer} = require '../../util'
bzipDeflate = require '../../../contrib/bzip_deflate'

#=================================================================================

make_too_large_err = () -> new Error "max length exceeded"

#
# Workaround browserify bug, not in use, see note right below.
#
#fake_zip_inflate = (buf, cb) ->
#  pako = require 'pako'
#  buf = Buffer.concat [ Buffer.from([0x78,0x9c]), buf ]
#  ret = null
#  try
#    ret = Buffer.from pako.inflate buf
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
fake_zip_inflate = (buf, max_length, cb) ->
  buf = Buffer.concat [ Buffer.from([0x78,0x9c]), buf ]
  # maxOutputLength only works with zlib.inflate, when using Inflate class
  # manually as a stream we will have to handle max_length ourselves here.
  zlib_opts = {
    flush : zlib.Z_FULL_FLUSH
  }
  inflater = zlib.createInflate zlib_opts

  cur_length = 0
  too_large = false
  bufs = []

  call_end = (err) ->
    if (tmp = cb)?
      # This actually isn't an error, so we're OK to ignore it... I think....
      if err? and err.code is "Z_BUF_ERROR" then err = null
      if too_large then err = make_too_large_err()
      cb = null
      if err? then ret = null else ret = Buffer.concat(bufs)
      tmp err, ret

  inflater.on 'readable', () ->
    return unless cb? # already exited, don't take more work
    while (read_buf = inflater.read())?
      cur_length += read_buf.length
      if max_length? and cur_length > max_length
        too_large = true
        inflater.close()
        call_end()
        break
      bufs.push read_buf
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

bzip_inflate = (buf, max_length, cb) ->
  err = null
  try
    ret = bzipDeflate buf, max_length
  catch e
    if e is "Max length exceeded"
      err = make_too_large_err()
    else if typeof e is 'string'
      # bzipDeflate code does `throw "foo"` instead of throwing Error objects
      err = new Error(e)
    else
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

  inflate : (opts, cb) ->
    err = ret = null
    max_length = opts?.max_length
    # Do not attempt to decompress data that already
    # exceeds max_length when compressed.
    if max_length? and @compressed.length > max_length
      return cb make_too_large_err()
    switch @algo
      when C.compression.none then ret = @compressed
      when C.compression.zlib
        zlib_opts = { maxOutputLength : max_length }
        await zlib.inflate @compressed, zlib_opts, defer err, ret
      when C.compression.zip
        await fake_zip_inflate @compressed, max_length, defer err, ret
      when C.compression.bzip
        await bzip_inflate @compressed, max_length, defer err, ret
      else
        err = new Error "no known inflation -- algo: #{@algo}"
    if err?.code is 'ERR_BUFFER_TOO_LARGE'
      err = make_too_large_err()
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
