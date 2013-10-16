
{Base} = require './base'
K = require('../../const').kb

#==================================================================================================

class SelfSignPgpUserid extends Base

  constructor : ({@key_wrapper, @userids}) ->
    super { type : K.sig_types.self_sign_pgp_username, key : @key_wrapper.key }

  _v_body : () ->
    return {
      ekid : @key_wrapper.key.ekid()
      generated : @key_wrapper.key.generated
      expire_in : @key_wrapper.key.expire_in
      username : @userids.get_openpgp()
    }

#==================================================================================================

class SelfSignKeybaseUsername extends Base

  constructor : ({@key_wrapper, @userids}) ->
    super K.sig_types.self_sign_keybase_username

  _v_body : () ->
    return {
      ekid : @key_wrapper.key.ekid()
      generated : @key_wrapper.key.generated
      expire_in : @key_wrapper.key.expire_in
      username : @userids.get_keybase()
    }

#==================================================================================================
