
{Packet} = require './base'
K = require('../../const').kb
sig = require './signature'
{Primary,Subkey,Lifespan} = require '../../keywrapper'

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
    await @verify_subkeys { primary, asp }, defer err, subkeys unless err?
    cb err, { primary, userid, subkeys }

  #-----------------

  _verify_subkey : ({asp, sigs}, cb) ->
    esc = make_err cb, "KeyBundle::_verify_subkey"
    await sigs.fwd.verify esc defer()
    await sigs.rev.verify esc defer()
    cb null

  #-----------------

  _destructure_subkey : (primary, obj, cb) ->
    ret = err = null
    try
      subkey = KeyMaterial.alloc(@is_private(), obj.key)
      key_wrapper = new Subkey { key : subkey.key, _keybase : subkey, primary }
      fwd = new sig.SubkeySignature { subkey : key_wrapper, sig : obj.sigs.forward  }
      rev = new sig.SubkeyReverse { subkey : key_wrapper, sig : obj.sigs.rev }
      ret = { key_wrapper, sig : { fwd, rev } }
    catch e
      err = e
    cb err, ret

  #-----------------

  verify_subkeys : ({primary, asp}, cb) ->
    esc = make_err cb, "KeyBundle::verify_subkeys"
    subkeys = @subkeys
    @subkeys = []
    ret = []
    for obj in subkeys
      await @_destructure_subkey primary, obj, esc defer { key_wrapper, sigs }
      await @_verify_subkey {asp, sigs}, esc defer()
      key_wrapper.lifespan = sigs.fwd.get_lifespan()
      ret.push key_wrapper
    cb null, ret

  #-----------------

  _destructure_primary : (cb) ->
    primary = @primary
    @primary = null
    err = ret = null
    try
      key = KeyMaterial.alloc(@is_private(), primary.key)
      sig = new sig.SelfSig { key, sig : primary.sig }
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
      userids : new UserIds { keybase : sig.userid }
    }
    cb null, ret

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

