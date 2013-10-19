
{Base} = require './base'
K = require('../../const').kb
{sign,verify} = require '../sign'
{Packet} = require './base'
{bufeq_secure,unix_time} = require '../../util'
{Lifespan} = require '../../keywrapper'

#==================================================================================================

class Base extends Packet
  constructor : ({@type,@key,@sig,@body}) ->

  #------

  sign : ({asp, include_body }, cb) ->
    body = @_v_body()
    await sign { @key, @type, body, include_body }, defer err, @sig
    cb err, @sig

  #------

  frame_packet : () ->
    super K.packet_tags.signature, @sig

  #------

  signing_ekid : () -> @body.ekid

  #------

  verify : (cb) ->
    err = null
    now = unix_time()
    @body = @sig.body unless @body?
    if (d = (now - (@body.generated + @body.expire_in))) > 0
      err = new Error "signature expired #{d}s ago"
    else if not bufeq_secure(@signing_ekid(), @key.ekid())
      err = new Error "trying to verify with the wrong key"
    else
      await verify { @type, @key, @sig, @body}, defer err
    cb err

  #------

  get_lifespan : () -> new Lifespan @body

#==================================================================================================

class SelfSign extends Base

  constructor : ({@key_wrapper, @userid, sig, body}) ->
    key = @key_wrapper.key
    super { type : K.sig_types.self_sign, key, sig, body }

  _v_body : () ->
    return {
      ekid : @key_wrapper.key.ekid()
      generated : @key_wrapper.lifespan.generated
      expire_in : @key_wrapper.lifespan.expire_in
      userid : @userid
    }

#==================================================================================================

class Subkey extends Base

  # @param {KeyWrapper} subkey The subkey, with a pointer back to the primary key
  constructor : ({@subkey, sig, body}) ->
    super { type : K.sig_types.subkey, key : @subkey.primary.key, sig, body }

  signing_ekid : () -> @body.primary_ekid

  _v_body : () ->
    return {
      primary_ekid : @subkey.primary.ekid()
      subkey_ekid  : @subkey.ekid()
      generated : @subkey.lifespan.generated
      expire_in : @subkey.lifespan.expire_in
    }

#==================================================================================================

class SubkeyReverse extends Base

  #
  # The only difference here is that we're signing wit the subkey, rather than
  # the primary key.  The payload is the same...
  #
  # @param {KeyWrapper} subkey The subkey, with a pointer back to the primary key
  constructor : ({@subkey, sig, body}) ->
    super { type : K.sig_types.subkey_reverse, key : @subkey.key, sig, body }

  signing_ekid : () -> @body.subkey_ekid

  _v_body : () ->
    return {
      primary_ekid : @subkey.primary.ekid()
      subkey_ekid  : @subkey.ekid()
      generated : @subkey.lifespan.generated
      expire_in : @subkey.lifespan.expire_in
    }

#=================================================================================

exports.SelfSign = SelfSign
exports.Subkey = Subkey
exports.SubkeyReverse = SubkeyReverse

#=================================================================================

