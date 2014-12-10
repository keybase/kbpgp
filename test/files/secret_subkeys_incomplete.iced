{KeyManager} = require '../../'
{bufferify,ASP} = require '../../lib/util'
{make_esc} = require 'iced-error'
util = require 'util'
{box} = require '../../lib/keybase/encode'
{Encryptor} = require 'triplesec'
{base91} = require '../../lib/basex'
{burn} = require '../../lib/openpgp/burner'
{do_message} = require '../../lib/openpgp/processor'

#---------------------------------------------

pub = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

mI0EU1UoTgEEAOMP1er7XCaXhVLeHGQK7KFanTTeSLvI39kBvlxQfIjOBjsFH2/J
3PtHazl2RGSzGqIPyqD+79TAwa15ESEDwwvwldJnlP9MwfwMk0HUeygqWbar9bj9
LTiPLlf/4z0a9GLjuBnI6Yuy7nutd0mKatR/2v2q0pI9WJaXOurhwATTABEBAAG0
IFdpbGxpYW0gV29yZHN3b3J0aCA8d3dAb3guYWMudWs+iL4EEwEKACgFAlNVKE4C
GwMFCRLMAwAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEJLYKARjvfT1roEE
AJ140DFf7DV0d51KMmwz8iwuU7OWOOMoOObdLOHox3soScrHvGqM0dg7ZZUhQSIE
TQUDk2Fkcjpqizhs7sJinbWYcpiaEKv7PWYHLyIIH+RcYKv18hlaEFHaOoUdRfzZ
sNSwNznnlCSCJOwkVMa1eJGJrEElzoktqPeDsforPFKhuI0EU1UoTgEEALCxOW1Y
5BQSOMoNdbby7uyS4hPaO0YVz9tvNdx+DZvNOmgmUw04Ex1EM8NNVxwmEBiPyRf1
YkNKP6CW4y+3fX2UusBeNquhke8cWolAPGWrJHeYKQhOMvT1QX/BXLewXvB6TwqU
m2FhKIFlPj3qjUw6yPmT4Txj+84dBu+D24rTABEBAAGIpQQYAQoADwUCU1UoTgIb
DAUJEswDAAAKCRCS2CgEY7309RooBACIrXNBBAg5WSoFr8T0nHlSkJUX9+LRexN9
TZjRKWAVXuP0Gp7ShvJwnYsVE0Od1VF4lBCPm+nBn8Hl0ChSpoxeYAPcMP7tljvn
q76DStTbVng1/7B709/IDn6XHD7o9c2lhzG9T3Bd/63m+9Mut2dUB1HSFLEpZ04K
AhLVWVC7Gw==
=jrB1
-----END PGP PUBLIC KEY BLOCK-----
"""

#------------

# In this case, we have only 1 subkey for encryption, and no
# subkeys for signing.  Plus, we don't have an encrypted primary
# key. So we shouldn't be able to sign.
priv = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQCVBFNVKE4BBADjD9Xq+1wml4VS3hxkCuyhWp003ki7yN/ZAb5cUHyIzgY7BR9v
ydz7R2s5dkRksxqiD8qg/u/UwMGteREhA8ML8JXSZ5T/TMH8DJNB1HsoKlm2q/W4
/S04jy5X/+M9GvRi47gZyOmLsu57rXdJimrUf9r9qtKSPViWlzrq4cAE0wARAQAB
/gNlAkdOVQG0IFdpbGxpYW0gV29yZHN3b3J0aCA8d3dAb3guYWMudWs+iL4EEwEK
ACgFAlNVKE4CGwMFCRLMAwAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEJLY
KARjvfT1roEEAJ140DFf7DV0d51KMmwz8iwuU7OWOOMoOObdLOHox3soScrHvGqM
0dg7ZZUhQSIETQUDk2Fkcjpqizhs7sJinbWYcpiaEKv7PWYHLyIIH+RcYKv18hla
EFHaOoUdRfzZsNSwNznnlCSCJOwkVMa1eJGJrEElzoktqPeDsforPFKhnQH+BFNV
KE4BBACwsTltWOQUEjjKDXW28u7skuIT2jtGFc/bbzXcfg2bzTpoJlMNOBMdRDPD
TVccJhAYj8kX9WJDSj+gluMvt319lLrAXjaroZHvHFqJQDxlqyR3mCkITjL09UF/
wVy3sF7wek8KlJthYSiBZT496o1MOsj5k+E8Y/vOHQbvg9uK0wARAQAB/gMDAmEI
mZFRPn111gNki6npnVhXyDhv7FWJw/aLHkEISwmK4fDKOnx+Ueef64K5kZdUmnBC
r9HEAUZA8mKuhWnpDTCLYZwaucqMjD0KyVJiApyGl9QHU41LDyfobDWn/LabKb6t
8uz6qkGzg87fYz8XLDgLvolImbTbeqQa9wuBRK9XfRLVgWv7qemNeDCSdLFEDA6W
ENR+YjDJTZzZDlaH0yLMvudJO4lKnsS+5lhX69qeBJpfp+eMsPh/K8dCOi6mYuSP
SF2JI7hVpk9PurDO1ne20mLuqZvmuDHcddWM88FjXotytDtuHScaX94+vVLXQAKz
mROs4Z7GkNs2om03kWCqsGmAV1B0+bbmcxTH14/vwAFrYSJwcvHsaDhshcCoxJa8
pKxttlHlUYQ6YQZflIMnxvbZAIryDDK9kwut3GGStfoJXoi5jA8uh+WG+avn+iNI
k8lR0SSgo6n5/vyWS6l/ZBbF1JwX6oQ4ep7piKUEGAEKAA8FAlNVKE4CGwwFCRLM
AwAACgkQktgoBGO99PUaKAQAiK1zQQQIOVkqBa/E9Jx5UpCVF/fi0XsTfU2Y0Slg
FV7j9Bqe0obycJ2LFRNDndVReJQQj5vpwZ/B5dAoUqaMXmAD3DD+7ZY756u+g0rU
21Z4Nf+we9PfyA5+lxw+6PXNpYcxvU9wXf+t5vvTLrdnVAdR0hSxKWdOCgIS1VlQ
uxs=
=NolW
-----END PGP PRIVATE KEY BLOCK-----
"""

#------------

book_first = """
O there is blessing in this gentle breeze,
A visitant that while it fans my cheek
Doth seem half-conscious of the joy it brings
From the green fields, and from yon azure sky.
Whate'er its mission, the soft breeze can come
To none more grateful than to me; escaped
From the vast city, where I long had pined
A discontented sojourner: now free,
Free as a bird to settle where I will.
"""

#------------

passphrase = "lucy"
km = null
km_priv = null

#------------

exports.load_pub = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : pub }, defer err, tmp, warnings
  km = tmp
  T.no_error err
  T.assert km?, "got a key manager back"
  cb()

#------------

exports.load_priv = (T,cb) ->
  await KeyManager.import_from_armored_pgp { raw : priv }, defer err, tmp, warnings
  km_priv = tmp
  T.no_error err
  throw err if err?
  T.assert km_priv, "got a private key manager back"
  cb()

#------------

exports.unlock_priv = (T,cb) ->
  await km_priv.unlock_pgp { passphrase }, defer err
  T.no_error err
  cb()

#------------

exports.merge = (T,cb) ->
  await km.merge_pgp_private { raw : priv }, defer err
  T.no_error err
  cb()

#------------

exports.unlock_merged = (T,cb) ->
  await km.unlock_pgp { passphrase }, defer err
  T.no_error err
  cb()

#------------

armored_sig = null
armored_ctext = null

exports.sign = (T,cb) ->
  sk = km.find_signing_pgp_key()
  T.assert not(sk?), "can't sign, don't have the right key!"
  cb()

#------------

exports.encrypt = (T,cb) ->
  ek = km.find_crypt_pgp_key()
  await burn { msg : book_first, encryption_key : ek }, defer err, tmp
  armored_ctext = tmp
  T.no_error err
  cb()

#------------

exports.decrypt = (T,cb) ->
  await do_message { armored : armored_ctext, keyfetch : km }, defer err, literals
  T.no_error err
  T.equal literals[0].toString(), book_first, "Book 1 of the prelude came back"
  T.assert not(literals[0].get_data_signer()?), "wasn't signed"
  cb()

#------------
