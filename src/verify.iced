
ukm = require './ukm'
{make_esc} = require 'iced-error'

exports.GenericKey = class GenericKey
  constructor : ({@km}) ->
  kid : () -> @km.get_ekid().toString('hex')
  isPGP : () -> !!@km.get_pgp_fingerprint()
  _verify_cb : (s, opts, cb) ->
    esc = make_esc cb
    sig_eng = @km.make_sig_eng()
    await sig_eng.unbox s, esc(defer(payload, body)), opts
    cb null, [payload, body]
  verify : (s, opts) ->
    new Promise ((resolve, reject) =>
      @_verify_cb(s, opts, (err, res) ->
        if err? then reject(err)
        else resolve(res)
      )
    )

import_key_cb = (s, opts, cb) ->
  esc = make_esc cb
  await ukm.import_armored_public { armored : s, opts }, esc defer km
  ret = new GenericKey { km }
  cb null, ret

exports.importKey = (s, opts) ->
  new Promise ((resolve, reject) ->
    import_key_cb(s, opts, (err, ret) ->
      if err? then reject(err)
      else resolve(ret)
    )
  )
