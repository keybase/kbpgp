{Canceler} = require 'iced-error'

#=========================================================

#
# Equivalent to this monstrosity you might see in OpenPgpJS:
#
#  var d = new Date();
#  d = d.getTime()/1000;
#  var timePacket = String.fromCharCode(Math.floor(d/0x1000000%0x100)) + String.fromCharCode(Math.floor(d/0x10000%0x100)) + String.fromCharCode(Math.floor(d/0x100%0x100)) + String.fromCharCode(Math.floor(d%0x100));
#
exports.make_time_packet = (d) ->
  d or= Math.floor(Date.now()/1000)
  b = new Buffer 4
  b.writeUInt32BE d, 0
  b

exports.uint_to_buffer = (nbits, i) ->
  ret = null
  switch nbits
    when 16
      ret = new Buffer 2
      ret.writeUInt16BE i, 0
    when 32
      ret = new Buffer 4
      ret.writeUInt32BE i, 0
    when 8
      ret = new Buffer 1
      ret.writeUInt8 i, 0
    else
      throw new Error "Bit types not found: #{nbit}"
  ret

#=========================================================

# ASync Package -- a collection of stuff that's
# often passed along an async chain to monitor progress,
# to insert delay slots, and also to cancel
#
exports.ASP = class ASP

  constructor : ({progress_hook, delay, canceler}) ->
    @_delay         = delay         or 2 # 2msec delay by default
    @_canceler      = canceler      or (new Canceler())
    @_progress_hook = progress_hook or ((obj) -> )
    @_section       = null

  section : (s) -> 
    @_section = s
    @

  progress : (o, cb) -> 
    o.section = @_section if @_section
    @_progress_hook o
    if cb?
      await @delay defer err
      cb err

  delay : (cb) -> 
    await setTimeout defer(), @delay
    cb @_canceler.err()

  canceler : () -> @_canceler

  progress_hook : () -> @_progress_hook

#=========================================================

exports.calc_checksum = calc_checksum = (text) ->
  ret = 0
  for i in [0...text.length]
    ret = (ret + text.readUInt8(i)) % 65536
  ret

#=========================================================

exports.encode_length = encode_length = (l) ->
  ret = null
  if l < 192
    ret = new Buffer 1
    ret.writeUInt8 l, 0
  else if l >= 192 and l < 8384
    ret = new Buffer 2
    ret.writeUInt16BE( ((l - 192) + (192 << 8 )), 0)
  else
    ret = new Buffer 5
    ret.writeUInt8 0xff, 0
    ret.writeUInt32BE l, 1
  ret

#=========================================================

exports.bufeq_fast = (x,y) ->
  return false unless x.length is y.length
  for i in [0...x.length]
    return false unless x.readUInt8(i) is y.readUInt8(i)
  return true

#-----

exports.bufeq_secure = (x,y) ->
  ret = true
  if x.length isnt y.length
    ret = false
  else
    check = 0
    for i in [0...x.length]
      check += (x.readUInt8(i) ^ y.readUInt8(i))
    ret = (check is 0)
  ret

#=========================================================

exports.bufferify = bufferify = (s) ->
  if Buffer.isBuffer(s) then s
  else if typeof s is 'string' then new Buffer 'utf8'
  else throw new Error "Cannot convert to buffer: #{s}"

#=========================================================

exports.katch = (fn) ->
  ret = err = null
  try ret = fn()
  catch e then err = e
  [err, ret]

#=========================================================

exports.buffer_to_ui8a = buffer_to_ui8a = (b) ->
  l = b.length
  ret = new Uint8Array l
  for i in [0...l]
    ret[i] = b.readUint8 i
  ret

#=========================================================

exports.nullthrow = (ret) ->

#=========================================================

exports.unix_time = () -> Math.floor(Date.now()/1000)

#=========================================================

