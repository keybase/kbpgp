bzipDeflate = require '../../contrib/bzip_deflate'
fs = require 'node:fs'
path = require 'node:path'

exports.rle2_buffer_overrun = (T, cb) ->
  payload_b64 = fs.readFileSync(path.join(__dirname, '..', 'data', 'fail-issue5747.bz2.base64'))
  payload = Buffer.from(payload_b64.toString('utf-8'), 'base64')

  err = ret = null
  try
    ret = bzipDeflate payload, undefined
  catch e
    err = e

  T.assert err?
  T.assert typeof err is 'string'
  T.equal err, "Block limit exceeded"
  T.assert not ret?

  cb null

exports.case_32767 = (T, cb) ->
  payload = fs.readFileSync(path.join(__dirname, '..', 'data', '32767.bz2'))

  err = ret = null
  try
    ret = bzipDeflate payload, undefined
  catch e
    err = e

  T.no_error err
  T.equal ret, Buffer.from("TEST\n")

  cb null

exports.case_32767_truncated = (T, cb) ->
  payload = fs.readFileSync(path.join(__dirname, '..', 'data', '32767_truncated.bz2'))

  err = ret = null
  try
    ret = bzipDeflate payload, undefined
  catch e
    err = e

  T.assert err?
  T.assert typeof err is 'string'
  T.equal err, "Unexpected end of bzip2 data"
  T.assert not ret?

  cb null