{make_esc} = require 'iced-error'
{OnePassSignature} = require './packet/one_pass_sig'
{Signature,CreationTime,Issuer} = require './packet/signature'
{export_key_pgp,get_cipher} = require '../symmetric'
{SEIPD,PKESK} = require './packet/sess'
{SHA512} = require '../hash'
{encode} = require './armor'
clearsign = require './clearsign'
{BaseBurner} = require './baseburner'
C = require('../const').openpgp
{unix_time} = require '../util'

#==========================================================

exports.BaseBurner = class BaseBurner

  #-----------------

  constructor : ({@sign_with, @encrypt_for, @signing_key, @encryption_key} ) ->
    @packets = []

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

  #------------

  _make_session_key : (cb) ->
    @_cipher_algo = C.symmetric_key_algorithms.AES256
    @_cipher_info = get_cipher @_cipher_algo
    await SRF().random_bytes @_cipher_info.key_size, defer @_session_key
    @_cipher = new @_cipher_info.klass WordArray.from_buffer @_session_key
    cb null

  #------------

  _encrypt_session_key : (cb) ->
    esc = make_esc cb, "_encrypt_session_key"
    payload = export_key_pgp @_cipher_algo, @_session_key
    pub_k = @encryption_key.key
    fingerprint = @encryption_key.get_fingerprint()
    await pub_k.pad_and_encrypt payload, {fingerprint}, esc defer ekey
    if @opts.hide
      key_id = dummy_key_id 
      await ekey.hide { max : @opts.hide?.max, slosh : @opts.hide?.slosh, key : pub_k }, esc defer()
    else 
      key_id = @encryption_key.get_key_id()
    pkt = new PKESK { 
      crypto_type : pub_k.type,
      key_id : key_id,
      ekey : ekey
    } 
    await pkt.write esc defer @_pkesk
    cb null

  #-----------------

  _setup_encryption : (cb) ->
    esc = make_esc cb, "_setup_encryption"
    await @_make_session_key esc defer()
    await @_encrypt_session_key esc defer()
    cb null, @_pkesk

  #-----------------

  _make_ops_packet : () ->
    return new OnePassSignature { 
      sig_type : C.sig_types.binary_doc,
      hasher : (@hasher or SHA512)
      sig_klass : @signing_key.get_klass()
      key_id : @signing_key.get_key_id()
      is_final : 1
    }

  #-----------------

  _make_sig_packet : ({hasher}) ->
    return new Signature {
      type : C.sig_types.binary_doc
      key : @signing_key.key
      hashed_subpackets : [ new CreationTime(unix_time()) ]
      unhashed_subpackets : [ new Issuer @signing_key.get_key_id() ]
      hasher : hasher
    }

#==========================================================

