
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
    if not(@signing_key?) and not(@encryption_keys?)
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

    count_true = (v...) ->
      i = 0
      (i++ for e in v when e)
      i

    arrayize = (e) ->
      if not e? then []
      else if typeof(e) is 'object' and Array.isArray(e) then e
      else [ e ]

    if count_true(@encrypt_for?, @encryption_key?, @encryption_keys?) > 1
      err = new Error "specify only one of `encrypt_for`, `encryption_keys` and `encryption_key`"
    else if @encrypt_for?
      @encryption_keys = []
      for f,i in (@encrypt_for = arrayize @encrypt_for)
        if (k = f.find_crypt_pgp_key())?
          @encryption_keys.push k
        else
          err = new Error "cannot encrypt with the given KeyManager (i=#{i})"
          break
    else if @encryption_key?
      @encryption_keys = [ @encryption_key ]
    else if @encryption_keys?
      @encryption_keys = arrayize @encryption_keys
    cb err

#==========================================================

