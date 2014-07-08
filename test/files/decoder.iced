
#-----------------------------------------

{decode} = require "../../lib/openpgp/armor"

#-----------------------------------------

orig = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

mI0EUqDRSAEEAMMt5Y4DoTF8g+2ahwPRNy9XOXvdGd3lvNnx/qpmnrogmQnTGgs6
pEu7EJWa4FG/omKK6YMY9EYrHUWs2yDZyazSP311GMKDvYAqVPdlk2ki3X57cf8f
hMuUuE9exj9rBP9XzIys8uj6+U/P/RrcdbZJ+XkggF54xwkwApShs93FABEBAAG0
KlRlc3QgTWNUZXN0ZWUgKHB3IGlzICdhJykgPHRlc3RAZ21haWwuY29tPoi9BBMB
CgAnBQJSoNFIAhsDBQkB4TOABQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJEJAS
rIm9T49IZvsEAI7jTFBn+VtJZklXJx5jUlbUN1CMDjs1QPI/NAeXZCgcsobplm9B
PEnMyG8z9zTmzI/0ZicntHJqIuJWMv8tTfn3JUdbYs6ISiXD3CFIDCd50XsEDScY
bZb9b9OLtEXrlPU9TL2m8y6B8aArfoFIjBLk3hDl1uTo3oasX10c8ZmzuI0EUqDR
SAEEALO/3L8r+vTMh4tNVQ6EdyMAKvgoBKaztg7+hNN/OKGCDMLf9ijLjVFIGRxF
iSGOXio2au6lHSPiwhSUEpvw73T2mJlJ4Phu01mqzvaffpFwbbd97zaJ+4cqyk3n
IwJeQCw8XGLkn39eDUMyhPaJqgS1FgavHNe1XW2i6ZUqi/AbABEBAAGIpQQYAQoA
DwUCUqDRSAIbDAUJAeEzgAAKCRCQEqyJvU+PSCdlA/9C5U+B3RI20m73qvMWd+mZ
NbmYAfD5ynHqLdBvLnsCD6EHdMKlyY6XDmj1z8jfwcBjbTa40U8qP6dEQTWBhHml
0E3713KUQeR2aYmt3hHBtQFDcVt7FfQImj4BIqJ+V6pNRLQCNOFbAC3RaXnwFMnN
RAA6k7dYVvv+36h0LfJGSQ==
=YJ8I
-----END PGP PUBLIC KEY BLOCK-----"""

inside = """mI0EUqDRSAEEAMMt5Y4DoTF8g+2ahwPRNy9XOXvdGd3lvNnx/qpmnrogmQnTGgs6
pEu7EJWa4FG/omKK6YMY9EYrHUWs2yDZyazSP311GMKDvYAqVPdlk2ki3X57cf8f
hMuUuE9exj9rBP9XzIys8uj6+U/P/RrcdbZJ+XkggF54xwkwApShs93FABEBAAG0
KlRlc3QgTWNUZXN0ZWUgKHB3IGlzICdhJykgPHRlc3RAZ21haWwuY29tPoi9BBMB
CgAnBQJSoNFIAhsDBQkB4TOABQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJEJAS
rIm9T49IZvsEAI7jTFBn+VtJZklXJx5jUlbUN1CMDjs1QPI/NAeXZCgcsobplm9B
PEnMyG8z9zTmzI/0ZicntHJqIuJWMv8tTfn3JUdbYs6ISiXD3CFIDCd50XsEDScY
bZb9b9OLtEXrlPU9TL2m8y6B8aArfoFIjBLk3hDl1uTo3oasX10c8ZmzuI0EUqDR
SAEEALO/3L8r+vTMh4tNVQ6EdyMAKvgoBKaztg7+hNN/OKGCDMLf9ijLjVFIGRxF
iSGOXio2au6lHSPiwhSUEpvw73T2mJlJ4Phu01mqzvaffpFwbbd97zaJ+4cqyk3n
IwJeQCw8XGLkn39eDUMyhPaJqgS1FgavHNe1XW2i6ZUqi/AbABEBAAGIpQQYAQoA
DwUCUqDRSAIbDAUJAeEzgAAKCRCQEqyJvU+PSCdlA/9C5U+B3RI20m73qvMWd+mZ
NbmYAfD5ynHqLdBvLnsCD6EHdMKlyY6XDmj1z8jfwcBjbTa40U8qP6dEQTWBhHml
0E3713KUQeR2aYmt3hHBtQFDcVt7FfQImj4BIqJ+V6pNRLQCNOFbAC3RaXnwFMnN
RAA6k7dYVvv+36h0LfJGSQ=="""

filler = """Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed  do
eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim
veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea
commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit
esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat
non proident, sunt in culpa qui officia deserunt mollit anim id est laborum
"""

#-------------------------------------

exports.test_freestanding = (T,cb) ->
  [err,msg] = decode orig
  T.no_error err
  T.assert msg, "got a message object back"
  T.equal msg.pre, "", "msg.pre is empty"
  T.equal msg.post, "", "msg.post is empty"
  T.equal msg.raw(), orig, "msg raw was right"
  T.equal msg.fields.type, "PUBLIC KEY BLOCK", "we expected a public key block"
  T.equal msg.fields.checksum, "YJ8I", "checksum was as expected"
  T.equal (inside.split('\n').join('')), msg.body.toString('base64'), 'base64 encode/decode worked'
  cb()

#-------------------------------------

exports.test_context_1 = (T,cb) ->
  text = [ filler,  orig , filler ].join "\n"
  [err,msg] = decode text 
  T.no_error err
  T.assert msg, "got a message object back"
  T.equal msg.pre, (filler + "\n"), "msg.pre = filler"
  T.equal msg.post, ("\n" + filler), "msg.post = filler"
  T.equal msg.fields.type, "PUBLIC KEY BLOCK", "we expected a public key block"
  T.equal msg.raw(), orig, "msg raw was right"
  cb()

#-------------------------------------

exports.test_context_2 = (T,cb) ->
  text = [ filler,  orig ].join("\n")
  [err,msg] = decode text 
  T.no_error err
  T.assert msg, "got a message object back"
  T.equal msg.pre, (filler + "\n"), "msg.pre = filler"
  T.equal msg.fields.type, "PUBLIC KEY BLOCK", "we expected a public key block"
  T.equal msg.raw(), orig, "msg raw was right"
  cb()

#-------------------------------------

exports.test_context_3 = (T,cb) ->
  text = orig + filler
  [err,msg] = decode text 
  T.no_error err
  T.assert msg, "got a message object back"
  T.equal msg.post, filler, "msg.post = filler"
  T.equal msg.fields.type, "PUBLIC KEY BLOCK", "we expected a public key block"
  T.equal msg.raw(), orig, "msg raw was right"
  cb()

#-------------------------------------

bad1 = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

mI0EUqDRSAEEAMMt5Y4DoTF8g+2ahwPRNy9XOXvdGd3lvNnx/qpmnrogmQnTGgs6
pEu7EJWa4FG/omKK6YMY9EYrHUWs2yDZyazSP311GMKDvYAqVPdlk2ki3X57cf8f
hMuUuE9exj9rBP9XzIys8uj6+U/P/RrcdbZJ+XkggF54xwkwApShs93FABEBAAG0
KlRlc3QgTWNUZXN0ZWUgKHB3IGlzICdhJykgPHRlc3RAZ21haWwuY29tPoi9BBMB
CgAnBQJSoNFIAhsDBQkB4TOABQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJEJAS
rIm9T49IZvsEAI7jTFBn+VtJZklXJx5jUlbUN1CMDjs1QPI/NAeXZCgcsobplm9B
PEnMyG8z9zTmzI/0ZicntHJqIuJWMv8tTfn3JUdbYs6ISiXD3CFIDCd50XsEDScY
bZb9b9OLtEXrlPU9TL2m8y6B8aArfoFIjBLk3hDl1uTo3oasX10c8ZmzuI0EUqDR
SAEEALO/3L8r+vTMh4tNVQ6EdyMAKvgoBKaztg7+hNN/OKGCDMLf9ijLjVFIGRxF
iSGOXio2au6lHSPiwhSUEpvw73T2mJlJ4Phu01mqzvaffpFwbbd97zaJ+4cqyk3n
IwJeQCw8XGLkn39eDUMyhPaJqgS1FgavHNe1XW2i6ZUqi/AbABEBAAGIpQQYAQoA
DwUCUqDRSAIbDAUJAeEzgAAKCRCQEqyJvU+PSCdlA/9C5U+B3RI20m73qvMWd+mZ
NbmYAfD5ynHqLdBvLnsCD6EHdMKlyY6XDmj1z8jfwcBjbTa40U8qP6dEQTWBhHml
0E3713KUQeR2aYmt3hHBtQFDcVt7FfQImj4BIqJ+V6pNRLQCNOFbAC3RaXnwFMnN
RAA6k7dYVvv+36h0LfJGSQ==
=YJ8i
-----END PGP PUBLIC KEY BLOCK-----"""

exports.failed_checksum_1 = (T,cb) ->
  [err,msg] = decode bad1
  T.assert err, "error happened"
  T.equal err.message, "checksum mismatch", "the right error message"
  cb()

#-------------------------------------

bad2 = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

mI0EUqDRSAEEAMMt5Y4DoTF8g+2ahwPRNy9XOXvdGd3lvNnx/qpmnrogmQnTGgs6
pEu7EJWa4FG/omKK6YMY9EYrHUWs2yDZyazSP311GMKDvYAqVPdlk2ki3X57cf8f
hMuUuE9exj9rBP9XzIys8uj6+U/P/RrcdbZJ+XkggF54xwkwApShs93FABEBAAG0
KlRlc3QgTWNUZXN0ZWUgKHB3IGlzICdhJykgPHRlc3RAZ21haWwuY29tPoi9BBMB
CgAnBQJSoNFIAhsDBQkB4TOABQsJCAcDBRUKCQgLBRYCAwEAAh4BAheAAAoJEJAS
rIm9T49IZvsEAI7jTFBn+VtJZklXJx5jUlbUN1CMDjs1QPI/NAeXZCgcsobplm9B
PEnMyG8z9zTmzI/0ZicntHJqIuJWMv8tTfn3JUdbYs6ISiXD3CFIDCd50XsEDScY
bZb9b9OLtEXrlPU9TL2m8y6B8aArfoFIjBLk3hDl1uTo3oasX10c8ZmzuI0EUqDR
SAEEALO/3L8r+vTMh4tNVQ6EdyMAKvgoBKaztg7+hNN/OKGCDMLf9ijLjVFIGRxF
iSGOXio2au6lHSPiwhSUEpvw73T2mJlJ4Phu01mqzvaffpFwbbd97zaJ+4cqyk3n
IwJeQCw8XGLkn39eDUMyhPaJqgS1FgavHNe1XW2i6ZUqi/AbABEBAAGIpQQYAQoA
DwUCUqDRSAIbDAUJAeEzgAAKCRCQEqyJvU+PSCdlA/9C5U+B3RI20m73qvMWd+mZ
NbmYAfD5ynHqLdBvLnsCD6EHdMKlyY6XDmj1z8jfwcBjbTa40U8qP6dEQTWBhHml
0E3713KUQeR2aYmt3hHBtQFDcVt7FfQImj4BIqJ+V6pNRLQCNOFbAC3RaXnwFMnN
RAA6k6dYVvv+36h0LfJGSQ==
=YJ8I
-----END PGP PUBLIC KEY BLOCK-----"""

exports.failed_checksum_2 = (T,cb) ->
  [err,msg] = decode bad2
  T.assert err, "error happened"
  T.equal err.message, "checksum mismatch", "the right error message"
  cb()

#-------------------------------------
