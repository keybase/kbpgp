
{Base} = require './base'
K = require('../../const').kb
{sign,verfiy} = require '../sign'
{Packet} = require './base'

#==================================================================================================

class Base extends Packet
  constructor : ({@type,@key}) ->
    @sig = null

  #------

  sign : ({asp}, cb) ->
    body = @_v_body()
    await sign { @key, @type, body }, defer err, @sig
    cb err, @sig

  #------

  frame_packet : () ->
    super K.packet_tags.signature, @sig

#==================================================================================================

class SelfSignPgpUserid extends Base

  constructor : ({@key_wrapper, @userids}) ->
    super { type : K.sig_types.self_sign_pgp_username, key : @key_wrapper.key }

  _v_body : () ->
    return {
      ekid : @key_wrapper.key.ekid()
      generated : @key_wrapper.lifespan.generated
      expire_in : @key_wrapper.lifespan.expire_in
      username : @userids.get_openpgp()
    }

#==================================================================================================

class SelfSignKeybaseUsername extends Base

  constructor : ({@key_wrapper, @userids}) ->
    super { type : K.sig_types.self_sign_keybase_username, key : @key_wrapper.key }

  _v_body : () ->
    return {
      ekid : @key_wrapper.key.ekid()
      generated : @key_wrapper.lifespan.generated
      expire_in : @key_wrapper.lifespan.expire_in
      username : @userids.get_keybase()
    }

#==================================================================================================

class SubkeySignature extends Base

  # @param {KeyWrapper} subkey The primary key
  constructor : ({@subkey}, cb) ->
    super { type : K.sig_types.subkey, key : @subkey.primary.key }

  _v_body : () ->
    return {
      primary_ekid : @subkey.primary.ekid()
      subkey_ekid  : @subkey.ekid()
      generated : @subkey.lifespan.generated
      expire_in : @subkey.lifespan.expire_in
    }

#=================================================================================

exports.SelfSignPgpUserid = SelfSignPgpUserid
exports.SelfSignKeybaseUsername = SelfSignKeybaseUsername
exports.SubkeySignature = SubkeySignature

#=================================================================================

