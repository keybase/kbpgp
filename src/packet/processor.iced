

#==========================================================================================

class Processor

  constructor : (@packets) ->
    # We'll throw away signatures that aren't verified.
    @verifed_signatures = []

  #--------------------

  verify_signatures : (cb) ->
    start = 0
    err = null
    key = primary = null

    for p,i in @packets
      if not primary? and p.is_key_material()
        primary = p
        key = p.key
      if p.is_signature()
        p.key = key
        p.primary = primary
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
