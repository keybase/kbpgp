K = require('../../const').kb
triplesec = require 'triplesec'
{SHA512} = require '../../hash'
{native_rng} = triplesec.prng
{Packet} = require './base'
{pack,box} = require '../encode'
{make_esc} = require 'iced-error'
rsa = require '../../rsa'
{sign,verify} = require '../sign'
{bufferify} = require '../../util'

#=================================================================================

class KeyMaterial extends Packet

  constructor : ({@key, @timestamp, @expires, @userid, @passphrase, @sig, @rawkey, @primary} ) ->
    super()

  #--------------------------

  _write_public : () ->
    pub = @key.pub.serialize()
    return { type : @key.type, pub, @timestamp, @expires, @userid }

  #--------------------------

  write_public : () ->
    body = @_write_public()
    @frame_packet K.packet_tags.public_key, body

  #--------------------------

  write_private : ({progress_hook}, cb) ->
    await @_write_private { progress_hook }, defer err, ret 
    if ret? then ret = @frame_packet K.packet_tags.public_key, ret
    cb err, ret

  #--------------------------

  _write_private : ({progress_hook}, cb) ->
    ret = @_write_public()
    priv = @key.priv.serialize()

    if @passphrase?
      await triplesec.encrypt { key : @passphrase, data : priv, progress_hook }, defer err, epriv
      if err? then ret = null
      else
        ret.priv = 
          data : epriv
          encryption : K.key_encryption.triplesec_v1
    else
      ret.priv = 
        data : priv
        encryption : K.key_encryption.none

    cb err, ret

  #--------------------------

  _encode_keys : ({progress_hook}, sig, cb) ->
    await @_write_private { progress_hook }, defer err, priv
    pub = @_write_public()
    ret = null
    {private_key, public_key} = K.message_types
    {packet} = K.genres
    # XXX always binary-encode for now (see Issue #7)
    unless err?
      ret = 
        private : (box { genre : packet, type : private_key, packet : { sig, @userid, key : priv }),
        public  : (box { genre : packet, type : public_key,  packet : { sig, @userid, key : pub })
    cb err, ret

  #--------------------------

  _self_sign_key : ( {hasher, progress_hook }, cb) ->
    hasher = SHA512 unless hasher?
    type = K.signatures.self_sign_key_pgp_username
    body = @_self_sign_body()
    await sign { @key, type, body, hasher, progress_hook }, defer err, res
    cb err, res

  #--------------------------

  _self_sign_body : () -> { @userid, key : @_write_public() }

  #--------------------------

  export_keys : ({armor, progress_hook}, cb) ->
    ret = err = null
    await @_self_sign_key {progress_hook}, defer err, sig
    unless err?
      await @_encode_keys { progress_hook }, sig, defer err, ret
    cb err, ret

  #--------------------------

  @alloc : (secret_tag, o) ->
    ret = null
    try
      ret = new KeyMaterial { 
        userid : o.userid, 
        timestamp : o.key.timestamp, 
        rawkey:
          type : o.key.type
          pub : o.key.pub,
          priv : o.key.priv 
        sig : o.sig  
      }
      throw new Error "didn't a private key" if secret_tag and not ret.rawkey.priv?
    catch e
      err = e 
    [err, ret]

  #--------------------------

  alloc_public_key : ({progress_hook}, cb) ->
    switch @rawkey.type
      when K.public_key_algorithms.RSA
        [ err, @key ] = rsa.RSA.alloc { pub : @rawkey.pub }
      else
        err = new Error "unknown key type: #{@rawkey.type}"
    cb err

  #--------------------------

  verify_self_sig : ({progress_hook}, cb) ->
    body = @_self_sign_body()
    type = K.signatures.self_sign_key_pgp_username
    await verify { @key, @sig, body, type, progress_hook }, defer err
    cb err

  #--------------------------

  unlock_private_key : ({passphrase, progress_hook}, cb) ->
    err = null
    if (k = @rawkey.priv)?
      switch k.encryption
        when K.key_encryption.triplesec_v1
          await triplesec.decrypt { key : passphrase, data: k.data }, defer err, raw
        when K.key_encryption.none
          raw = k.data
        else
          err = new Error "Unknown key encryption type: #{k.encryption}"
      err = @key.read_priv raw unless err?
    cb err

  #--------------------------

  # Open a keybase secret key packet, with the given passphrase.
  #
  # @param {string} passphrase the utf8-string that's the passphrase.
  # @param {callback} cb Callback with `null` if it worked, or an {Error} otherwise
  #
  open : ({passphrase, progress_hook}, cb) ->
    passphrase = bufferify passphrase 
    esc = make_esc cb, "KeyMaterial::esc"
    err = null
    await @alloc_public_key {progress_hook}, esc defer()
    await @verify_self_sig {progress_hook}, esc defer()
    await @unlock_private_key {passphrase, progress_hook}, esc defer()
    cb err
  
  #--------------------------

#=================================================================================

exports.KeyMaterial = KeyMaterial
