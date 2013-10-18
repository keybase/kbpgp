
{Base} = require './base'
K = require('../../const').kb
{sign,verfiy} = require '../sign'
{Packet} = require './base'
{bufeq_secure,unix_time} = require '../../util'

#==================================================================================================

class Base extends Packet
  constructor : ({@type,@key}) ->
    @sig = null

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
    if @body.generated isnt @key.timestamp
      err = new Error "Timestamp generation mistmatch: #{@body.generated} != #{@key.timestamp}"
    else if (d = (now - (@body.generated + @body.expire_in))) > 0
      err = new Error "signature expired #{d}s ago"
    else if not bufeq_secure(@signing_ekid(), @key.ekid())
      err = new Error "trying to verify with the wrong key"
    else
      await verify { @type, @key, @sig, @body}, defer err
    cb err


#==================================================================================================

class SelfSignPgpUserid extends Base

  constructor : ({@key_wrapper, @userids}) ->
    super { type : K.sig_types.self_sign_pgp_userid, key : @key_wrapper.key }

  _v_body : () ->
    return {
      ekid : @key_wrapper.key.ekid()
      generated : @key_wrapper.lifespan.generated
      expire_in : @key_wrapper.lifespan.expire_in
      username : @userids.get_openpgp()
    }

#==================================================================================================

class SelfSignPgpUserid extends Base

  constructor : ({@key_wrapper, @userids}) ->
    super { type : K.sig_types.self_sign_pgp_userid, key : @key_wrapper.key }

  _v_body : () ->
    return {
      ekid : @key_wrapper.key.ekid()
      generated : @key_wrapper.lifespan.generated
      expire_in : @key_wrapper.lifespan.expire_in
      username : @userids.get_openpgp()
    }

#==================================================================================================

class SelfSignKeybaseUsername extends Base

  constructor : ({@key_wrapper, key, @userids}) ->
    key = @key_wrapper?.key unless key?
    super { type : K.sig_types.self_sign_keybase_username, key }


  _v_body : () ->
    return {
      ekid : @key_wrapper.key.ekid()
      generated : @key_wrapper.lifespan.generated
      expire_in : @key_wrapper.lifespan.expire_in
      username : @userids.get_keybase()
    }

#==================================================================================================

class SubkeySignature extends Base

  # @param {KeyWrapper} subkey The subkey, with a pointer back to the primary key
  constructor : ({@subkey}) ->
    super { type : K.sig_types.subkey, key : @subkey.primary.key }

  signing_ekid : () -> @body.primary_ekid

  _v_body : () ->
    return {
      primary_ekid : @subkey.primary.ekid()
      subkey_ekid  : @subkey.ekid()
      generated : @subkey.lifespan.generated
      expire_in : @subkey.lifespan.expire_in
    }

#==================================================================================================

class SubkeyReverseSignature extends Base

  #
  # The only difference here is that we're signing wit the subkey, rather than
  # the primary key.  The payload is the same...
  #
  # @param {KeyWrapper} subkey The subkey, with a pointer back to the primary key
  constructor : ({@subkey}) ->
    super { type : K.sig_types.subkey_reverse, key : @subkey.key }

  signing_ekid : () -> @body.subkey_ekid

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
exports.SubkeyReverseSignature = SubkeyReverseSignature

#=================================================================================

