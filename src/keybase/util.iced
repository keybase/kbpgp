
{SRF} = require '../rand'

#======================================================

exports.bufxor = bufxor = (b1, b2) ->
  arr = (c^b2[i] for c,i in b1)
  return new Buffer arr

#======================================================

exports.genseed = genseed = ({seed, split, len, server_half}, cb ) ->
  err = rseed = null
  server_half = null unless server_half?

  if not seed? or (split and not server_half?)
    await SRF().random_bytes len, defer rseed
  if seed? and seed.length isnt len 
    err = new Error "Wrong seed length; need #{len} bytes; got #{seed.length}"
  else if seed? and rseed?
    server_half = rseed
    seed = bufxor seed, rseed
  else if seed? and server_half?
    seed = bufxor seed, server_half
  else if not seed?
    seed = rseed
    
  cb err, { seed, server_half }

