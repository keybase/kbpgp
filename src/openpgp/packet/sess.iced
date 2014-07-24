
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
hashmod = require '../../hash'
{SHA1} = hashmod
{xxd,bufcat,uint_to_buffer,bufeq_secure,bufeq_fast} = require '../../util'
{encrypt,Encryptor,Decryptor} = require '../ocfb'
{Packetizer} = require './xbt_packetizer'
xbt = require '../../xbt'
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

  constructor : ( { @ciphertext }) ->

  @parse : (slice) -> (new SEIPD_Parser slice).parse()

  #------

  @TAG : C.packet_tags.SEIPD
  TAG : SEIPD.TAG

  #------

  to_enc_data_packet : () -> @

  check : () ->

  #------

  decrypt : (cipher) ->
    eng = new Decryptor { cipher, ciphertext : @ciphertext }
    err = eng.check()
    throw err if err?
    pt = eng.dec()
    [ mdc, plaintext ] = MDC.parse pt
    prefix = eng.get_prefix()

    # check that the hash matches what we fetched out of the message
    mdc.compute { prefix, plaintext }
    throw new Error "MDC mismatch" unless mdc.check()

    plaintext

  #------

  encrypt : ({cipher, plaintext, prefixrandom }, cb) ->
    mdc = new MDC {}
    mdc_buf = mdc.compute { plaintext, prefix : prefixrandom }
    plaintext = Buffer.concat [ plaintext, MDC.header, mdc_buf ]
    await encrypt { cipher, plaintext, prefixrandom }, defer err, @ciphertext
    cb err

  #------

  write_unframed : (cb) ->
    err = ret = null
    bufs = [ uint_to_buffer(8, C.versions.SEIPD) ]
    bufs.push(@ciphertext) if @ciphertext?
    ret = Buffer.concat(bufs)
    cb err, ret

  #------

  new_xbt : ( { pkesk, cipher, prefixrandom } ) -> new SEIPD_XbtOut { pkesk, packet : @, cipher, prefixrandom }

#=================================================================================

exports.SEIPD_XbtOut = class SEIPD_XbtOut extends Packetizer

  constructor : ({packet, @pkesk, cipher, prefixrandom }) ->
    super { packet } 
    @_mdc = new MDC { }
    @_mdc_xbt = @_mdc.new_xbt { prefixrandom }
    @_ocfb = new Encryptor { cipher, prefixrandom }
    @_ocfb.set_parent(@)

  #----------------

  xbt_type : () -> "SEIPD.XbtOut"

  #----------------

  _v_init : (cb) ->
    # Prefix our packet with the full PKESK packet (see above)
    await super defer err, out
    if not err? then out = bufcat [ @pkesk, out ]
    cb err, out

  #----------------

  _v_chunk : ({data, eof}, cb) ->
    esc = make_esc cb, "SEIPD_XbtOut::_v_chunk"

    # Will only output a SHA1 digest in an EOF situation
    await @_mdc_xbt.chunk { data, eof }, esc defer out

    # Append the MDC packet to the end of the stream, and then, in turn,
    # we'll encrypt it with the OCFB encryption stream.
    data = bufcat [ data, out ]

    # Get the encrypted data... 
    await @_ocfb.chunk { data, eof }, esc defer out

    # And pass our output up to the superclass, which will packetize it accordingly,
    # along 64k boundaries
    await super { data : out, eof }, esc defer out

    cb null, out

#=================================================================================

# 5.14.  Modification Detection Code Packet (Tag 19)
class MDC extends Packet

  @header : new Buffer [ (0xc0 | C.packet_tags.MDC ), SHA1.output_length ]
  header  : MDC.header
  constructor : ({@digest}) ->
  @parse : (buf) -> (new MDC_Parser buf).parse()

  compute : ({plaintext, prefix}) ->
    @computed = SHA1 Buffer.concat [ prefix, prefix[-2...], plaintext, @header ]
    @computed

  check : () -> bufeq_secure @digest, @computed

  @TAG : C.packet_tags.MDC
  TAG : MDC.TAG

  write_unframed : (cb) -> 
    out = @digest or (new Buffer [])
    cb null, out

  new_xbt : ({prefixrandom}) -> new MDC_XbtOut { mdc : @, prefixrandom }

#=================================================================================

exports.MDC_XbtOut = class MDC_XbtOut extends xbt.Base

  constructor : ({@mdc, prefixrandom}) ->
    @hasher = hashmod.streamers.SHA1()
    @hasher.update prefixrandom
    @hasher.update prefixrandom[-2...]

  xbt_type : () -> "MDC.XbtOut"

  chunk : ( {data, eof}, cb) ->
    esc = make_esc cb, "MDC_XbtOut::chunk"
    @hasher.update(data) if data?
    err = out = null
    if eof
      @hasher.update @mdc.header
      @mdc.digest = @hasher()
      await @mdc.write esc defer out
    cb err, out

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
    throw new Error 'Missing MDC header' unless bufeq_fast chunk[0...hl], MDC.header
    digest = chunk[hl...]
    [ new MDC({ digest }), rem ]

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
