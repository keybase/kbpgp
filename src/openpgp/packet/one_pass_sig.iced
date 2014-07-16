
{Packet} = require './base'
C = require('../../const').openpgp
asymmetric = require '../../asymmetric'
hash = require '../../hash'
{uint_to_buffer} = require '../../util'
xbt = require '../../xbt'
{make_esc} = require 'iced-error'

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
    unless (v = @slice.read_uint8()) is C.versions.one_pass_sig
      throw new Error "Unknown OnePassSignature version #{v}"
    sig_type = @slice.read_uint8()
    hasher = hash.alloc_or_throw @slice.read_uint8()
    sig_klass = asymmetric.get_class @slice.read_uint8() 
    key_id = @slice.read_buffer 8
    is_final = @slice.read_uint8()
    new OnePassSignature { sig_type, hasher, sig_klass, key_id, is_final }

#=================================================================================

exports.OnePassSignature = OnePassSignature

#=================================================================================

exports.XbtOut = class XbtOut extends xbt.SimpleInit

  constructor : ({@header, @footer, literal}) ->
    super()
    @_literal_xbt = literal.new_xbt()

  _v_init : (cb) -> @header.write cb

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
