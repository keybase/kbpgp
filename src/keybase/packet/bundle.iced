
{Packet} = require './base'
K = require('../../const').kb
sigmod = require './signature'
{UserIds,Primary,Subkey,Lifespan} = require '../../keywrapper'
{KeyMaterial} = require './keymaterial'
{katch} = require '../../util'
{make_esc} = require 'iced-error'

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

  set_primary : (obj) -> @primary = obj
  push_subkey : (sk) -> @subkeys.push sk

  #-----------------

  @alloc : ({tag, body}) ->
    body = {} unless body?
    switch tag
      when K.packet_tags.public_key_bundle  then new PublicKeyBundle body
      when K.packet_tags.private_key_bundle then new PrivateKeyBundle body
      else
        throw new Error "not a key bundle (tag=#{tag})"

  #-----------------

  @alloc_nothrow : (obj) -> katch () -> KeyBundle.alloc obj

  #-----------------

  verify : ({asp}, cb) ->
    await @verify_primary { asp }, defer err
    await @verify_subkeys { asp }, defer err unless err?
    cb err

  #-----------------

  export_to_obj : () -> { @primary,  @userids, @subkeys }

  #-----------------

  _verify_subkey : ({asp, sigs}, cb) ->
    esc = make_esc cb, "KeyBundle::_verify_subkey"
    await sigs.fwd.verify esc defer()
    await sigs.rev.verify esc defer()
    cb null

  #-----------------

  _destructure_subkey : (obj, cb) ->
    ret = err = null
    try
      subkey = KeyMaterial.alloc(@is_private(), obj.key)
      key_wrapper = new Subkey { key : subkey.key, _keybase : subkey, @primary }
      fwd = new sigmod.Subkey { subkey : key_wrapper, sig : obj.sigs.forward  }
      rev = new sigmod.SubkeyReverse { subkey : key_wrapper, sig : obj.sigs.reverse }
      ret = { key_wrapper, sigs : { fwd, rev } }
    catch e
      err = e
    cb err, ret

  #-----------------

  verify_subkeys : ({primary, asp}, cb) ->
    esc = make_esc cb, "KeyBundle::verify_subkeys"
    subkeys = @subkeys
    @subkeys = []
    ret = []
    for obj in subkeys
      await @_destructure_subkey obj, esc defer { key_wrapper, sigs }
      await @_verify_subkey {asp, sigs}, esc defer()
      key_wrapper.lifespan = sigs.fwd.get_lifespan()
      ret.push key_wrapper
    @subkeys = ret
    cb null

  #-----------------

  _destructure_primary : (cb) ->
    raw_obj = @primary
    @primary = null
    err = ret = null
    try
      km = KeyMaterial.alloc(@is_private(), raw_obj.key)
      key_wrapper = new Primary { key : km.key, _keybase : km }
      sig = new sigmod.SelfSign { key_wrapper, sig : raw_obj.sig }
      ret = {key_wrapper, sig }
    catch e
      err = e
    cb err, ret

  #-----------------

  verify_primary : ({asp}, cb) ->
    esc = make_esc cb, "KeyBundle::verify_primary"
    await @_destructure_primary esc defer { key_wrapper, sig }
    await sig.verify esc defer()
    @primary = key_wrapper
    @primary.lifespan = sig.get_lifespan()
    @userids = new UserIds { keybase : sig.userid }
    cb null

#=================================================================

class PublicKeyBundle extends KeyBundle
  constructor : ({primary, subkeys}) ->
    super { primary, subkeys, tag : K.packet_tags.public_key_bundle }
  is_private : () -> false

#=================================================================

class PrivateKeyBundle extends KeyBundle
  constructor : ({primary, subkeys}) ->
    super { primary, subkeys, tag : K.packet_tags.private_key_bundle }
  is_private : () -> true

#=================================================================

exports.PublicKeyBundle = PublicKeyBundle
exports.PrivateKeyBundle = PrivateKeyBundle
exports.KeyBundle = KeyBundle

#=================================================================

