
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
hash = require '../../hash'
{uint_to_buffer} = require '../../util'
xbt = require '../../xbt'
{make_esc} = require 'iced-error'
{PacketParser} = require './xbt_depacketizer'

#=================================================================================

# 5.4. One-Pass Signature Packets (Tag 4)
class OnePassSignature extends Packet

  @TAG : C.packet_tags.one_pass_sig
  TAG : OnePassSignature.TAG

  #---------------

  constructor : ( {@sig_type, @hasher, @sig_klass, @key_id, @is_final }) ->

  #---------------

  @parse : (slice) -> (new OPS_Parser slice).parse()

  #---------------

  new_xbt : ({sig, literal}) -> new XbtOut { header : @, footer : sig, literal }
  @new_xbt_parser : (arg) -> new XbtIn arg

  #---------------

  write_unframed : (cb) ->
    vals = [
      C.versions.one_pass_sig, 
      @sig_type,
      @hasher.type,
      @sig_klass.type
    ]
    bufs = (uint_to_buffer(8,x) for x in vals)
    bufs.push @key_id
    bufs.push uint_to_buffer(8,@is_final)
    unframed = Buffer.concat bufs
    cb null, unframed

#=================================================================================

class OPS_Parser 

  constructor : (@slice) ->

  #  The body of this packet consists of:
  #
  #   - A one-octet version number.  The only currently defined value is 1.
  #   - Encrypted data, the output of the selected symmetric-key cipher
  #     operating in Cipher Feedback mode with shift amount equal to the
  #     block size of the cipher (CFB-n where n is the block size).
  parse : () -> 
    version = @slice.read_uint8()
    sig_type = @slice.read_uint8()
    hasher = @slice.read_uint8()
    sig_klass = @slice.read_uint8() 
    key_id = @slice.read_buffer 8
    is_final = @slice.read_uint8()
    OPS_Parser._alloc { version, sig_type, hasher, sig_klass, key_id, is_final }

  #----------------

  @_alloc : ({version, sig_type, hasher, sig_klass, key_id, is_final, streaming}) ->
    unless version is C.versions.one_pass_sig
      throw new Error "Unknown OnePassSignature version #{version}"
    hasher = hash.alloc_or_throw hasher, streaming
    sig_klass = asymmetric.get_class sig_klass
    new OnePassSignature { sig_type, hasher, sig_klass, key_id, is_final }

  #----------------

  @alloc : (args, cb) ->
    ret = err = null
    try ret = @_alloc(args)
    catch e then err = e
    cb err, ret

#=================================================================================

exports.OnePassSignature = OnePassSignature

#=================================================================================

exports.XbtOut = class XbtOut extends xbt.SimpleInit

  constructor : ({@header, @footer, literal}) ->
    super()
    @_literal_xbt = literal.new_xbt()

  _v_init : (cb) -> 
    await @header.write defer err, buf
    cb err, buf

  _v_chunk : ({data, eof}, cb) ->
    esc = make_esc cb, "XbtOut"
    @footer.hasher.update(data) if data?
    bufs = []
    await @_literal_xbt.chunk {data, eof}, esc defer b
    bufs.push b if b?
    if eof
      await @footer.write (new Buffer []), esc defer ftr
      bufs.push ftr
    cb null, (Buffer.concat bufs)

#=================================================================================

exports.XbtIn = class XbtIn extends PacketParser

  constructor : (arg) ->
    super arg

  xbt_type : () -> "OnePassSignature.XbtIn"

  _parse_header : (cb) ->
    err = null
    esc = make_esc cb, "_parse_header"
    await @_read_uint8 esc defer version
    await @_read_uint8 esc defer sig_type
    await @_read_uint8 esc defer hasher
    await @_read_uint8 esc defer sig_klass
    await @_read { exactly : 8 }, esc defer key_id
    await @_read_uint8 esc defer is_final
    aargs = { streaming : true, version, sig_type, hasher, sig_klass, key_id, is_final }
    await OPS_Parser.alloc aargs, esc defer packet
    @get_root().push_hasher packet.hasher
    console.log "all done, got packet ->"
    console.log packet
    console.log @_inq
    await @set_root_metadata { slice : 'ops', value : packet }, esc defer()
    cb null

  # No 'body' of a one-pass-signature packet, it's all Header.
  _run_body : (cb) -> cb null

#=================================================================================
