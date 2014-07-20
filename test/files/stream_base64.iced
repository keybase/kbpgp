
main = require '../../'
{util,armor} = main
C = main.const
xbt = require '../../lib/xbt'
{Faucet,Drain} = require 'iced-stream'

#---------------------------------------------------------------------

msg = """
-----BEGIN PGP MESSAGE-----
Version: GnuPG v1

owEBSQK2/ZANAwACAS/gHEVDSNo5AcsZYgBTyzLsdGVzdCBtZXNzYWdlIDEgMiAz
CokCHAQAAQIABgUCU8sy7AAKCRAv4BxFQ0jaObtKD/4uxOcz9Ivo8YQMmY7mgUAn
sTAzcUsLn2y0LUurAIAez0BtgRSyDPdl02DSicsjVXGELUL1CAEKZkQ5fyzMUmnO
y13BjON2k985E549gsTZULNn2ZP8KSkN5rKarsyWr7ZA9BrBjSocbt2AT9ce8GAj
cuvIEwbk38RllLbyWMhZ0t1OJnl4pymbjpMUb/NsUnRFwwmmpHP8dmkhIk4zRlMI
QfsIGz26DtaotzdPyQ90loQBHnVicpL9thuu3d43sG/GE0HJE0a7Q2Obl9nEjZRq
7TfS9vI7vTrdQnqPXeSJVh0PBADMPO2nm2scqHLX/u9azrXpqSFxYJvJwZItvjVJ
OxKlE1Yxd6e46P1lE2HHut62XrRrri0no6BnHxWa8BAq2p0brQOGt6c/vTlMp1ck
Rb+D7pZv7ZuRJb8w/rBsv7nQG8uuq2axr4IxKmpMRgjiGIHQp2UD+9jUr3meF5+x
phlkygGN6GILkWKWEg/mj47ciBqLKV+CYpWRcyzeucTkE/LQaxaMYpzLOwMVqkyX
F2FAhCJAH8fCNJCy07vHOfVs7Tp9N5bCiw4+fmPnsudAzgcSFm+3AEHdNmLhGLYl
DDzZoVz3MsImZzGXbGwYFTxo5rv1e1o0qwCBMRm9W9faQJMCwtP6TfW0K16vKFJD
UnZPtobSm8qqDh3CFPKpmg==
=m+Ki
-----END PGP MESSAGE-----
"""

#---------------------------------------------------------------------

class SlowWriter

  constructor : ({@buf, @stream, @chunk_size}) ->
    @chunk_size or= 7

  pipe : (cb) ->
    err = null
    i = 0
    while i < @buf.length
      end = i + @chunk_size
      await @stream.write @buf[i...end], defer err
      break if err?
      await setTimeout defer(), 1
      i = end
    cb err

#---------------------------------------------------------------------

dearmor64 = (T,buf,cb) ->
  stream = new xbt.StreamAdapter { xbt : new armor.XbtDearmorer }
  drain = new Drain
  stream.pipe(drain)
  sw = new SlowWriter { buf, stream }
  await sw.pipe defer err
  T.no_error
  cb drain.data()

#---------------------------------------------------------------------

round_trip = (T, type, data, cb) ->
  b64 = armor.encode type, data
  await dearmor64 T, b64, defer data_out
  T.assert util.bufeq_fast(data, data_out), "data_in is data_out"
  cb()

#---------------------------------------------------------------------

exports.dearmor_pgp_out = (T,cb) -> 
  await dearmor64 T,msg, defer()
  cb()

#---------------------------------------------------------------------

exports.dearmor_round_trip_1 = (T,cb) ->
  buf = Buffer.concat ((new Buffer [0...i]) for i in [0...50])
  await round_trip T, C.openpgp.message_types.generic, buf, defer()
  cb()

#---------------------------------------------------------------------




