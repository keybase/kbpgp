#
# Clearsign ---
#
#    Like burner.iced, but for clear-signing only.
# 
#==========================================================================================

{make_esc} = require 'iced-error'
{Signature,CreationTime,Issuer} = require './packet/signature'
{bufferify,unix_time} = require '../util'
{SRF} = require '../rand'
triplesec = require 'triplesec'
{export_key_pgp,get_cipher} = require '../symmetric'
{scrub_buffer} = triplesec.util
{WordArray} = triplesec
konst = require '../const'
C = konst.openpgp
Ch = require '../header'
hashmod = require '../hash'
{SHA512} = hashmod
{encode} = require './armor'
{clearsign_header} = require('pgp-utils').armor
{Literal} = require "./packet/literal"

#==========================================================================================

exports.input_to_cleartext = input_to_cleartext = (raw) ->

  lines = raw.split /\n/

  ret =
    show : bufferify(input_to_cleartext_display(lines)),
    sign : bufferify(input_to_cleartext_sign(lines))

  return ret

#==========================================================================================

exports.dash_escape = dash_escape = (line) ->
  if (line.length >= 1 and line[0] is '-') then ("- " + line[1...]) else line

#==========================================================================================

exports.dash_unescape_line = dash_unescape_line = (line) ->
  warn = false
  out = if (m = line.match /^-( )?(.*?)$/)? 
    warn = true
    m[2]
  else
    line
  return [out, warn]

#==========================================================================================

exports.dash_unescape_lines = dash_unescape_lines = (lines, warnings = null) ->
  ret = for line,i in lines
    [l,warn] = dash_unescape_line line
    warnings?.push "Bad dash-encoding on line #{i+1}" if warn
    l
  return ret

#==========================================================================================

exports.input_to_cleartext_display = input_to_cleartext_display = (lines) ->
  out = (dash_escape(line) for line in lines)
  out.push '' if lines.length is 0  or lines[-1...][0] isnt ''
  out.join("\n")

#==========================================================================================

exports.clearsign_to_sign = clearsign_to_sign = (lines, warnings) ->
  lines = dash_unescape_lines lines, warnings
  input_to_cleartext_sign lines

#==========================================================================================

exports.input_to_cleartext_sign = input_to_cleartext_sign = (lines) ->
  tmp = (whitespace_strip(line) for line in lines)
  num_trailing_newlines = 0
  for t in tmp by -1
    if t is '' then num_trailing_newlines++
    else break
  if num_trailing_newlines > 0 then tmp.pop()
  return tmp.join("\r\n")

#==========================================================================================

exports.whitespace_strip = whitespace_strip = (line) ->
  line = line.replace /\r/g, ''
  if (m = line.match /^(.*?)([ \t]*)$/) then m[1] else line

#==========================================================================================

class ClearSigner

  #------------

  # @param {Buffer} msg the message to clear sign
  # @param {openpgp.packet.KeyMaterial} signing_key the key to find
  constructor : ({@msg, @signing_key}) ->

  #------------

  _fix_msg : (cb) ->
    @_cleartext = input_to_cleartext @msg.toString('utf8')
    cb null

  #------------

  _sign_msg : (cb) ->
    @sig = new Signature {
      sig_type : C.sig_types.canonical_text
      key : @signing_key.key
      hashed_subpackets : [ new CreationTime(unix_time()) ]
      unhashed_subpackets : [ new Issuer @signing_key.get_key_id() ]
    }
    await @sig.write @_cleartext.sign, defer err, @_sig_output
    cb err, @_sig_output

  #------------

  scrub : () ->

  #------------

  hasher_name : () -> @sig.hasher.algname

  #------------

  _encode : (cb) ->
    hdr = clearsign_header Ch, @_cleartext.show, @hasher_name()
    body = encode(C.message_types.signature, @_sig_output)
    cb null, (hdr+body)

  #------------

  run : (cb) ->
    esc = make_esc cb, "ClearSigner::run"
    await @_fix_msg esc defer()
    await @_sign_msg esc defer signature
    await @_encode esc defer encoded
    cb null, encoded, signature

#==========================================================================================

class Verifier 

  #---------------

  # @param {Array<openpgp.packet.base.Packet}>} packets and array of packets that came out of
  #    parsing the body of the PGP signature block.
  # @param {Object} clearsign the clearsign object that was embedded in the armor `Message`
  #    after parsing.
  #
  constructor : ({@packets, @clearsign, @key_fetch}) ->

  #-----------------------

  _find_signature : (cb) ->
    err = if (n = @packets.length) isnt 1 
      new Error "Expected one signature packet; got #{n}"
    else if (@_sig = @packets[0]).tag isnt C.packet_tags.signature 
      new Error "Expected a signature packet; but got type=#{@packets[0].tag}"
    else
      null
    cb null

  #-----------------------

  _reformat_text : (cb) ->
    data = bufferify clearsign_to_sign @clearsign.lines
    @_literal = new Literal {
      data : data,
      format : C.literal_formats.utf8,
      date : unix_time()
    }
    cb null

  #-----------------------

  _fetch_key : (cb) ->
    await @key_fetch.fetch [ @_sig.get_key_id() ], konst.ops.verify, defer err, obj
    unless err?
      @_sig.key = obj.key
      @_sig.hasher = hashmod[@clearsign.headers.hash]
      @_sig.keyfetch_obj = obj
    cb err

  #-----------------------

  _verify : (cb) ->
    await @_sig.verify [ @_literal ], defer err
    cb err

  #-----------------------

  run : (cb) ->
    esc = make_esc cb, "Verifier::run"
    await @_find_signature esc defer()
    await @_reformat_text esc defer()
    await @_fetch_key esc defer()
    await @_verify esc defer()
    cb null, @_literal

#==========================================================================================

# @param {Buffer} msg the message to clear sign
# @param {openpgp.packet.KeyMaterial} signing_key the key to find
# @param {Callback<error,String,Buffer>} cb with the error (if there was one)
#    the string of the PGP message, and finally the raw signature.
exports.sign = ({msg, signing_key}, cb) ->
  b = new ClearSigner { msg, signing_key }
  await b.run defer err, encoded, signature
  b.scrub()
  cb err, encoded, signature

#==========================================================================================

exports.verify = ({packets, clearsign, key_fetch}, cb) ->
  v = new Verifier { packets, clearsign, key_fetch }
  await v.run defer err, literal
  cb err, literal

#==========================================================================================
