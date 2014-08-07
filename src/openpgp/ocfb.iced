##  Modified by Recurity Labs GmbH
##  modified version of http://www.hanewin.net/encrypt/PGdecode.js:
##  OpenPGP encryption using RSA/AES
##  Copyright 2005-2006 Herbert Hanewinkel, www.haneWIN.de
##  version 2.0, check www.haneWIN.de for the latest version
##
##  This software is provided as-is, without express or implied warranty.
##  Permission to use, copy, modify, distribute or sell this software, with or
##  without fee, for any purpose and by any individual or organization, is hereby
##  granted, provided that the above copyright notice and this paragraph appear
##  in all copies. Distribution as a part of an application or binary must
##  include the above copyright notice in the documentation and/or other
##  materials provided with the application or distribution.
##
## *
##  An array of bytes, that is integers with values from 0 to 255
##  @typedef {(Array|Uint8Array)} openpgp_byte_array
## /
## *
##  Block cipher function
##  @callback openpgp_cipher_block_fn
##  @param {openpgp_byte_array} block A block to perform operations on
##  @param {openpgp_byte_array} key to use in encryption/decryption
##  @return {openpgp_byte_array} Encrypted/decrypted block
## /
##  --------------------------------------
## *
##  This function encrypts a given with the specified prefixrandom
##  using the specified blockcipher to encrypt a message
##  @param {String} prefixrandom random bytes of block_size length provided
##   as a string to be used in prefixing the data
##  @param {openpgp_cipher_block_fn} blockcipherfn the algorithm encrypt function to encrypt
##   data in one block_size encryption.
##  @param {Integer} block_size the block size in bytes of the algorithm used
##  @param {String} plaintext data to be encrypted provided as a string
##  @param {openpgp_byte_array} key key to be used to encrypt the data. This will be passed to the
##   blockcipherfn
##  @param {Boolean} resync a boolean value specifying if a resync of the
##   IV should be used or not. The encrypteddatapacket uses the
##   "old" style with a resync. Encryption within an
##   encryptedintegrityprotecteddata packet is not resyncing the IV.
##  @return {String} a string with the encrypted data
## /

{WordArray} = require 'triplesec'
{SlicerBuffer} = require './buffer'
triplesec = require 'triplesec'
{AES} = triplesec.ciphers
{ASP} = require('pgp-utils').util
{make_esc} = require 'iced-error'

#===============================================================================

repeat = (b, n) -> Buffer.concat [ b, b[(b.length - n)...] ]

#===============================================================================

class Base

  #-------------

  constructor : ({@block_cipher_class, key, @cipher, @resync, asp}) ->
    @block_cipher_class or= AES
    @cipher or= new @block_cipher_class WordArray.from_buffer key
    @block_size = @cipher.blockSize
    @out_bufs = []
    @asp = ASP.make asp

  #-------------

  compact : () ->
    b = Buffer.concat @out_bufs
    @out_bufs = [ b ]
    b

#===============================================================================

class Encryptor extends Base

  #-------------

  constructor : ({block_cipher_class, key, cipher, prefixrandom, resync, asp}) ->
    super { block_cipher_class, key, cipher, resync, asp}
    @_init prefixrandom

  #-------------

  _enc : () ->
    @FRE = WordArray.from_buffer @FR
    @cipher.encryptBlock @FRE.words, 0

  #-------------

  _emit_sb : (sb) ->
    buf = if (deficit = @block_size - sb.rem()) > 0
      pad = new Buffer( 0 for i in [0...deficit])
      Buffer.concat [ sb.consume_rest_to_buffer(), pad ]
    else sb.read_buffer @block_size
    @_emit_buf buf

  #-------------

  _emit_buf : (buf) ->
    wa = WordArray.from_buffer buf[0...@block_size]
    wa.xor @FRE, {n_words : (Math.min wa.words.length, @FRE.words.length) }
    buf = wa.to_buffer()
    @out_bufs.push buf
    @FR = new Buffer buf

  #-------------

  _init : (prefixrandom) ->

    # 1. The feedback register (FR) is set to the IV, which is all zeros.
    @FR = new Buffer(0 for i in [0...@block_size])
    prefixrandom = repeat prefixrandom, 2

    # 2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
    #     encryption of an all-zero value.
    @_enc()

    # 3.  FRE is xored with the first BS octets of random data prefixed to
    #     the plaintext to produce C[1] through C[BS], the first BS octets
    #     of ciphertext.
    # 4.  FR is loaded with C[1] through C[BS]
    @_emit_buf prefixrandom


    # 5.  FR is encrypted to produce FRE, the encryption of the first BS
    #    octets of ciphertext.
    @_enc()

    # 6.  The left two octets of FRE get xored with the next two octets of
    #     data that were prefixed to the plaintext.  This produces C[BS+1]
    #     and C[BS+2], the next two octets of ciphertext.
    b = @FRE.to_buffer()
    canary = new Buffer((b.readUInt8(i) ^ prefixrandom.readUInt8(@block_size+i)) for i in [0...2])
    @out_bufs.push canary

    # 7.  (The resync step) FR is loaded with C3-C10.
    offset = if @resync then 2 else 0
    ct = @compact()
    ct.copy(@FR,0,offset,offset+@block_size)

    # 8.  FR is encrypted to produce FRE.
    @_enc()

  #-------------

  enc : (plaintext, cb) ->
    sb = new SlicerBuffer plaintext
    esc = make_esc cb, "Encryptor::enc"

    if @resync
      @_emit_sb sb
    else
      # 9. FRE is xored with the first 8 octets of the given plaintext, now
      #    That we have finished encrypting the 10 octets of prefixed data.
      #    This produces C11-C18, the next 8 octets of ciphertext.
      buf = Buffer.concat [ new Buffer([0,0]), sb.read_buffer(@block_size-2) ]
      wa = WordArray.from_buffer buf
      wa.xor @FRE, {}
      buf = wa.to_buffer()[2...]
      @out_bufs.push buf
      ct = @compact()
      ct.copy(@FR,0,ct.length - @block_size,ct.length)

    total = sb.rem()
    await @asp.progress { what : "ofcb encryption", i : 0, total }, esc defer()

    while (j = sb.rem())

      for [0...4096]
        @_enc()
        @_emit_sb sb
        break unless (j = sb.rem())

      await @asp.progress { what : "ofcb encryption", i : (total - j), total }, esc defer()

    ret = @compact()
    n_wanted = plaintext.length + @block_size + 2
    ret = ret[0...n_wanted]

    cb null, ret

#===============================================================================

class Decryptor extends Base

  #-------------

  constructor : ({block_cipher_class, key, cipher, prefixrandom, resync, @ciphertext, asp}) ->
    super { block_cipher_class, key, cipher, resync, asp}
    @_init()

  #-------------

  _init : () ->
    @reset()

  #-------------

  reset : () -> @sb = new SlicerBuffer @ciphertext

  #-------------

  next_block : () -> WordArray.from_buffer @sb.read_buffer_at_most @block_size

  #-------------

  get_prefix : () -> @_prefix

  #-------------

  check : (cb) ->
    @reset()
    iblock = new WordArray(0 for i in [0...@block_size/4])
    @cipher.encryptBlock iblock.words, 0
    ablock = @next_block()
    iblock.xor ablock, {}
    @_prefix = iblock.to_buffer()
    @cipher.encryptBlock ablock.words, 0

    # the last two bytes in iblock
    lhs = (iblock.words[-1...][0] & 0xffff)
    rhs = (ablock.words[0] >>> 16) ^ (@sb.peek_uint16())

    err = if lhs is rhs then null else new Error "Canary block mismatch: #{lhs} != #{rhs}"
    cb err

  #-------------

  dec : (cb) ->
    @reset()
    if @resync then @sb.advance 2
    iblock = @next_block()
    esc = make_esc cb, "Decryption::dec"

    total = @sb.rem()
    await @asp.progress { what : "ofcb decrypt", i : 0, total }, esc defer()

    while (j = @sb.rem())

      for [0...4096]
        ablock = iblock
        @cipher.encryptBlock ablock.words, 0
        iblock = @next_block()
        ablock.xor iblock, {}
        @out_bufs.push ablock.to_buffer()[0...iblock.sigBytes]
        break unless (j = @sb.rem())

      await @asp.progress { what : "ofcb decrypt", i :  (total - j), total }, esc defer()

    out = @compact()
    if not @resync then out = out[2...]
    cb null, out

#===============================================================================

encrypt = ({block_cipher_class, key, cipher, prefixrandom, resync, plaintext, asp}, cb) ->
  eng = new Encryptor { block_cipher_class, key, cipher, prefixrandom, resync, asp }
  eng.enc plaintext, cb

#===============================================================================

decrypt = ({block_cipher_class, key, cipher, resync, ciphertext, asp}, cb) ->
  eng = new Decryptor { block_cipher_class, key, cipher, resync, ciphertext, asp }
  await eng.check defer err
  await eng.dec defer err, pt unless err?
  cb err, pt

#===============================================================================

exports.encrypt = encrypt
exports.decrypt = decrypt
exports.Decryptor = Decryptor

#===============================================================================

{rng} = require 'crypto'
test = () ->
  plaintext = new Buffer("a man a plan a canal panama. and you know the rest")
  key = rng(32)
  prefixrandom = new Buffer [0...16]
  block_cipher_class = AES
  ct = encrypt { block_cipher_class, key, prefixrandom, plaintext }
  console.log ct.toString('hex')
  pt = decrypt {block_cipher_class, key, prefixrandom, ciphertext : ct }
  console.log pt.toString('utf8')

#test()

#===============================================================================

