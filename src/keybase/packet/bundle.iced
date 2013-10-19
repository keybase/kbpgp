
{Packet} = require './base'
K = require('../../const').kb

#=================================================================

class KeyBundle extends Packet

  constructor : ( {@primary, @subkeys, @tag}) ->
    @primary or= {}
    @subkeys or= []

  #-----------------
  
  frame_packet : () ->
    body = { @primary, @subkeys }
    super @tag, body 

  #-----------------

  set_primary : (obj) -> @primary = p
  push_subkey : (sk) -> @subkeys.push sk

  #-----------------

  @alloc : ({tag, body}) ->
    err = null
    bundle = switch tag
      when K.packet_tags.public_key_bundle  then new PublicKeyBundle body
      when K.packet_tags.private_key_bundle then new PrivateKeyBundle body
      else
        err = new Error "not a key bundle (tag=#{tag})"
        null
    [err, bundle]

  #-----------------

  verify : ({asp}, cb) ->
    await @verify_primary { asp }, defer err, { primary, userid } 
    await @verify_subkeys { asp }, defer err, subkeys unless err?
    cb err 

  #-----------------

  _destructure_primary : (cb) ->
    primary = @primary
    @primary = null
    err = ret = null
    try
      key = KeyMaterial.alloc(@is_private(), primary.key),
      sig = BaseSig.alloc {raw : primary.sigs.keybase, key, type : K.sig_types.self_sign }
      ret = {key,sig}
    catch e
      err = e
    cb err, ret

  #-----------------

  verify_primary : ({asp}, cb) ->
    esc = make_err cb, "KeyBundle::verify_primary"
    await @_destructure_primary esc defer { key, sig }
    await sig.verify esc defer()
    ret = { 
      primary : new Primary {
        key : key.key,
        lifespan : sig.get_lifespan(),
        _keybase : key
      }
      userids : new UserIds { keybase : sig.username }
    }
    cb ret

#=================================================================

class PublicKeyBundle extends KeyBundle
  constructor : ({primary, subkeys}) ->
    super { primary, subkeys, tag : K.packet_tags.public_key_bundle }

#=================================================================

class PrivateKeyBundle extends KeyBundle
  constructor : ({primary, subkeys}) ->
    super { primary, subkeys, tag : K.packet_tags.private_key_bundle }

#=================================================================

exports.PublicKeyBundle = PublicKeyBundle
exports.PrivateKeyBundle = PrivateKeyBundle
exports.KeyBundle = KeyBundle

#=================================================================

