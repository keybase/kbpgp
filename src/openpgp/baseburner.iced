
{make_esc} = require 'iced-error'
{ASP} = require('pgp-utils').util

#==========================================================

exports.BaseBurner = class BaseBurner

  #-----------------

  constructor : ({@sign_with, @encrypt_for, @signing_key, @encryption_key, @asp} ) ->
    @asp = ASP.make @asp

  #-----------------

  _find_keys : (cb) ->
    esc = make_esc cb, "find_keys"
    await @_find_signing_key esc defer()
    await @_find_encryption_key esc defer()
    await @_assert_one esc defer()
    cb null

  #-----------------

  _assert_one : (cb) ->
    err = null
    if not(@signing_key?) and not(@encryption_key?)
      err = new Error "need either an encryption or signing key, or both"
    cb err

  #-----------------

  _find_signing_key : (cb) ->
    err = null
    if @sign_with? and @signing_key?
      err = new Error "specify either `sign_with` or `signing_key` but not both"
    else if @sign_with? and not (@signing_key = @sign_with.find_signing_pgp_key())?
      err = new Error "cannot sign with the given KeyManager"
    cb err

  #-----------------

  _find_encryption_key : (cb) ->
    err = null
    if @encrypt_for? and @encryption_key?
      err = new Error "specify either `encrypt_for` or `encryption_key` but not both"
    else if @encrypt_for? and not (@encryption_key = @encrypt_for.find_crypt_pgp_key())?
      err = new Error "cannot encrypt with the given KeyManager"
    cb err

#==========================================================

