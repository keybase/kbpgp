
stream = require 'stream'

#
# InitableTransform --- just like stream.Transform, but with an initialization step.
# Very useful throughout the streaming system.
#
#===========================================================================

exports.InitableTransform = class InitableTransform extends stream.Transform

  #-----------------------------------------

  constructor : () ->
    super()
    @_did_init = false

  #-----------------------------------------

  _emit_err : (err) ->
    if err? then @emit 'error', err

  #-----------------------------------------

  _do_init : (cb) ->
    err = null
    unless @_did_init
      @_did_init = true
      await @_v_init defer err
      @_emit_err(err) if err?
    cb err

  #-----------------------------------------

  _transform : (buf, encoding, cb) ->
    await @_do_init defer err
    unless err?
      await @_v_transform buf, encoding, defer err
      @_emit_err(err) if err?
    cb()

  #-----------------------------------------

  _flush : (cb) ->
    await @_do_init defer err
    unless err?
      await @_v_flush defer err
      @_emit_err(err) if err?
    cb()

#===========================================================================


