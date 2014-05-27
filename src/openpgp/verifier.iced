
konst = require '../const'
C = konst.openpgp

#======================================================

exports.Base = class Base

  #-----------------------

  constructor : ({@packets, @keyfetch}) ->
    @_sig = null

  #-----------------------

  _find_signature : (cb) ->
    err = if (n = @packets.length) isnt 1 
      new Error "Expected one signature packet; got #{n}"
    else if (@_sig = @packets[0]).tag isnt C.packet_tags.signature 
      new Error "Expected a signature packet; but got type=#{@packets[0].tag}"
    else
      null
    cb err

  #-----------------------

  _fetch_key : (cb) ->
    await @keyfetch.fetch [ @_sig.get_key_id() ], konst.ops.verify, defer err, obj
    unless err?
      @_sig.key = obj.key
      @_sig.keyfetch_obj = obj
    cb err
  
#======================================================

