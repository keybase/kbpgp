
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
{SHA1,streamers} = require '../../hash'
{uint_to_buffer,bufeq_secure} = require '../../util'
{encrypt,Decryptor} = require '../ocfb'
{ASP} = require('pgp-utils').util
{make_esc} = require 'iced-error'

#=================================================================================

# 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
class PKESK extends Packet
  constructor : ( {@crypto_type, @key_id, @ekey }) ->
  @parse : (slice) -> (new PKESK_Parser slice).parse()
  to_esk_packet : () -> @
  get_key_id : () -> @key_id

  #------

  write_unframed : (cb) ->
    bufs = [
      uint_to_buffer(8, C.versions.PKESK)
      @key_id,
      uint_to_buffer(8, @crypto_type),
      @ekey.output()
    ]
    ret = Buffer.concat bufs
    err = null
    cb err, ret

  #------

  write : (cb) ->
    ret = null
    await @write_unframed defer err, unframed
    unless err?
      ret = @frame_packet C.packet_tags.PKESK, unframed
    cb err, ret

#=================================================================================

# 5.13.  Sym. Encrypted Integrity Protected Data Packet (Tag 18)
class SEIPD extends Packet

  constructor : ( { @ciphertext} ) ->

  @parse : (slice) -> (new SEIPD_Parser slice).parse()

  #------

  to_enc_data_packet : () -> @

  check : () ->

  #------

  decrypt : ({cipher, asp}, cb) ->
    eng = new Decryptor { cipher, ciphertext : @ciphertext, asp }
    esc = make_esc cb, "SEIPD::decrypt"
    asp = ASP.make asp

    await eng.check defer err
    await eng.dec esc defer pt

    [ valid_mdc, mdc, plaintext ] = MDC.parse pt
    prefix = eng.get_prefix()

    # check that the hash matches what we fetched out of the message
    await mdc.compute { prefix, plaintext, asp }, esc defer()
    valid_hash = mdc.check()

    # If we got an error or if the MDC is invalid, collapse that into
    # one non-descript error. Make sure we don't return plaintext.
    if err or not (valid_mdc and valid_hash)
      plaintext = null
      err = new Error "Unable to decrypt"

    cb err, plaintext

  #------

  encrypt : ({cipher, plaintext, prefixrandom , asp}, cb) ->
    mdc = new MDC {}
    esc = make_esc cb, "SEIPD::encrypt"
    asp = ASP.make asp
    await mdc.compute { plaintext, prefix : prefixrandom, asp }, esc defer mdc_buf
    plaintext = Buffer.concat [ plaintext, MDC.header, mdc_buf ]
    await encrypt { cipher, plaintext, prefixrandom }, esc defer @ciphertext
    cb null

  #------

  write_unframed : (cb) ->
    err = ret = null
    ret = Buffer.concat [ uint_to_buffer(8, C.versions.SEIPD), @ciphertext ]
    cb err, ret

  #------

  write : (cb) ->
    ret = err = null
    await @write_unframed defer err, unframed
    unless err?
      ret = @frame_packet C.packet_tags.SEIPD, unframed
    cb err, ret

#=================================================================================

# 5.14.  Modification Detection Code Packet (Tag 19)
class MDC extends Packet
  @header : Buffer.from [ (0xc0 | C.packet_tags.MDC ), SHA1.output_length ]
  header  : MDC.header
  constructor : ({@digest}) ->
  @parse : (buf) -> (new MDC_Parser buf).parse()

  #-----------------------

  compute : ({plaintext, prefix, asp}, cb) ->
    asp = ASP.make asp
    hasher = streamers.SHA1()
    hasher.update Buffer.concat [ prefix, prefix[-2...] ]
    esc = make_esc cb, "MDC::compute"

    step = 0x100000
    for i in [0...plaintext.length] by step
      hasher.update plaintext[i...(i+step)]
      await asp.progress { what : "MDC", total : plaintext.length, i  }, esc defer()

    hasher.update @header
    @computed = hasher()

    cb null, @computed

  #-----------------------

  check : () -> bufeq_secure @digest, @computed

#=================================================================================

class MDC_Parser

  #----------

  constructor : (@buf) ->

  #----------

  parse : () ->
    hl = MDC.header.length
    len = SHA1.output_length + hl
    rem = @buf[0...(-len)]
    chunk = @buf[(-len)...]
    valid = bufeq_secure chunk[0...hl], MDC.header
    digest = chunk[hl...]
    [ valid, new MDC({ digest }), rem ]

#=================================================================================

class SEIPD_Parser

  constructor : (@slice) ->

  payload_split : (raw) ->

  #  The body of this packet consists of:
  #
  #   - A one-octet version number.  The only currently defined value is 1.
  #   - Encrypted data, the output of the selected symmetric-key cipher
  #     operating in Cipher Feedback mode with shift amount equal to the
  #     block size of the cipher (CFB-n where n is the block size).
  parse : () ->
    throw new Error "Unknown SEIPD version #{v}" unless (v = @slice.read_uint8()) is C.versions.SEIPD
    ciphertext = @slice.consume_rest_to_buffer()
    new SEIPD { ciphertext }

#=================================================================================

class PKESK_Parser

  constructor : (@slice) ->

  # 5.1.  Public-Key Encrypted Session Key Packets (Tag 1)
  # Format:
  #    - 1 byte version ( == 3)
  #    - 8 byte Key Fingerprint
  #    - 1 byte CryptoSystem type
  #    - variable length MPIs
  #
  parse : () ->
    throw new Error "Unknown PKESK version: #{v}" unless (v = @slice.read_uint8()) is C.versions.PKESK
    key_id = @slice.read_buffer 8
    crypto_type = @slice.read_uint8()
    klass = asymmetric.get_class crypto_type
    ekey = klass.parse_output @slice.consume_rest_to_buffer()
    new PKESK { crypto_type, key_id, ekey }

#=================================================================================

exports.SEIPD = SEIPD
exports.PKESK = PKESK
exports.MDC = MDC

#=================================================================================
