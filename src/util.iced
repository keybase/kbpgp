{Canceler} = require 'iced-error'

#=========================================================

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
  else if typeof s is 'string' then new Buffer s, 'utf8'
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
    ret[i] = b.readUInt8 i
  ret

#=========================================================

exports.ui32a_to_ui8a = ui32a_to_ui8a = (v, out = null) ->
  out or= new Uint8Array v.length * 4
  k = 0
  for w in v
    out[k++] = (w >> 24) & 0xff
    out[k++] = (w >> 16) & 0xff
    out[k++] = (w >> 8 ) & 0xff
    out[k++] = (w      ) & 0xff
  out

#=========================================================

exports.ui8a_to_ui32a = ui8Ga_to_ui32a = (v, out = null) ->
  out or= new Uint32Array (v.length >> 2)
  k = 0
  for b,i in v by 4
    tmp = (b << 24) + (v[i+1] << 16) + (v[i+2] << 8) + v[i+3]
    out[k++] = tmp
  out

#=========================================================

exports.unix_time = () -> Math.floor(Date.now()/1000)

#=========================================================

