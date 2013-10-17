

#==========================================================================================

class Processor

  constructor : (@packets) ->
    # We'll throw away signatures that aren't verified.
    @verified_signatures = []
    @subkeys = []
    @primary = null

  #--------------------

  extract_keys : () ->
    for p,i in @packets when p.is_key_material()
      if p.is_primary() then @primary = p
      else @subkeys.push p

  #--------------------

  verify_signatures : (cb) ->
    start = 0
    err = null

    @extract_keys()

    if not @primary
      err = new Error "Cannot find a primary key in packet"
    else  
      for p,i in @packets
        if p.is_signature()
          p.key = @primary.key
          p.primary = @primary
          data_packets = @packets[start...i]
          await p.verify data_packets, defer tmp
          if tmp?
            console.log "Error in signature verification: #{tmp.toString()}"
            err = tmp
            # discard the signature, see the above comment...
          else
            @verified_signatures.push p
          start = i + 1
    cb err

  #--------------------

#==========================================================================================

exports.Processor = Processor

#==========================================================================================
