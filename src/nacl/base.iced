
{BaseKeyPair} = require '../basekeypair'

#=============================================

exports.BaseKeyPair = class Pair extends BaseKeyPair

  #----------------

  export_secret_key_kb : (args, cb) ->
    err = res = null
    if not (res = @priv?.key)? then err = new Error "no private key available"
    cb err, res

  #----------------

#=============================================

