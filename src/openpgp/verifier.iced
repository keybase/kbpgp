
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
    key_id = @_sig.get_key_id()
    await @keyfetch.fetch [ key_id ], konst.ops.verify, defer err, km, i
    unless err?
      keymat = km.find_pgp_key_material key_id
      @_sig.key = keymat.key
      @_sig.key_manager = km
      @_sig.subkey_material = keymat
    cb err

#======================================================

