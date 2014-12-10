{parse} = require '../../lib/openpgp/parser'
armor = require '../../lib/openpgp/armor'
C = require '../../lib/const'
{do_message,Message} = require '../../lib/openpgp/processor'
util = require 'util'
{unix_time,katch,ASP} = require '../../lib/util'
{KeyManager} = require '../../'
{import_key_pgp} = require '../../lib/symmetric'
{decrypt} = require '../../lib/openpgp/ocfb'
{PgpKeyRing} = require '../../lib/keyring'
{Literal} = require '../../lib/openpgp/packet/literal'
{burn} = require '../../lib/openpgp/burner'
clearsign = require '../../lib/openpgp/clearsign'
detachsign = require '../../lib/openpgp/detachsign'
hashmod = require '../../lib/hash'

#===============================================================================

message = """
-----BEGIN PGP MESSAGE-----
Charset: UTF-8
Version: End-To-End v0.3.1337

wf8AAACMAzE3gKsczTvwAQQAhCwBRYAjxk2Zc1Exf98fiC3rT6ntAsh6FHT1ayee
ZIb+KMybq5ZQruCoCfHkQJ0ANfnObqhXxDjE7bTTKz+f9eqwLOfikdQVxWfUn7Tn
nTOPhlKHlvn8X7KXbD1MX7C7rKESMFwZ1pM3jkEi+gNvJKYdyxVxqhw3eYvC0pKN
nn3B/wAAAQwDYuz2Vj187EwBCACbsTZ0MK3KLUUsMlj3vfu3vntIPny+R3wxseAM
9R5PH0BJ37vHP9YOoVjpSpLLaUU9u+JdRMISjq/SJRwMORZSplEEr9syG16rcz8V
69OF86ofeVrBmeXh7N9Wh5KY2HJz2J6T6+e1B1UATKVEM+lRk32xUB/h5GDn7+hE
MOwY9IdFfCt6htenGVKl/9apd5OtrjHuTunOsTwNkMLztgXf7S/DE3/n/c4KYvrv
cO/a4+IroOgXpVkGM0H92XEwT2IjFDPezn/cof/bUSyFQH7S1NVPTA+24sBMalsX
65BGFvkmeXf/Fjf4934wmbsKfSAplTYiDFOY1+SxVuqSKz3s0v8AAAHdAT/RPLFk
D/BOQoNzKuOwgaFRO/FJoCbp/Q1g0NaUFP//VCMoudUO3oI+nT1KZjH7mK8nyFxi
FaSFnbY707WGTuWwLycnNCsk5vypBJcDIEXrZwr6PD1KnMbWWDusP0qe63ITGzSn
1zeG59bjKbVY07ozh+MBTs2/ffXmjOL3BJZzFiAuYkLcNzboDxvP/nak9XggH4ab
TiUPcR7w18WzHrNVqKYljH6SxnaY3+LDZg257q9zp87d2GaBeYq11MBV47CPCj1Z
MufWnI/LR8knv3l1bMdHWn2rVMNikj2Mhkx5UXneuFBGkElgnynCbbcNQuX1rUNI
IT2jlOArgKeJekEpb2BnFHzENkq784TWepFDs2NilZBApplCOdvgS/gOYw2ntxqi
qaGMfLvsmXoKwzIEpaVL+SfxVyOoI8vZ1STWsIQ6M9pUXkSQw1vMFo1dR/FzJCky
Q1RsWHwucFXPLk6QutuKK5wr8PSRZvnchJwQGVhthAwQOmT2F7hXiv0imX4F/HUw
pnBlo+rIGQVaZaULwLJew3HP6QSfV/oOymiHNFkxztm0pvpByor9uom4DezlJmqw
FVmRsvMbo8KpVZcDjqvbh7Jhkso3mErCgOeEhFVU4FztMMz2is8z
=yWmD
-----END PGP MESSAGE-----
"""

sender = """
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFLXMzcBCADirGjknCEDPJkBJtESaojbcHlm5dFXVu/qb2Hs5qAoOjTt6pBH
3pSuG6GMwASzQd2zfLqyKTKard+BXq/d+FoKHACAHpQF+Yx9yaMYaC6IKty08kBY
uEndQXv95bFtfq6eiM+pDW4kOFNGNatZU69DbVhB4cE5yhaYJ3jvAud2ijpySWbO
Y3fll+xBYLZuCAcVtwllMEZhUPS9n62+UXsqUFo6NZDS+bDyUdAjwig8DlzrtcL4
0UGuDXmYRRn+GqSLDPPUm4VUmS+z12V1AFlbLysirWUjnfEKV1e0Ka+b2kc+67Cy
rgR7KsUnNQnadTbBwzSXRD8PXRqFLXsGr0QDABEBAAG0JUJyb3duIEhhdCAocHcg
aXMgJ2EnKSA8YnJvd25AaGF0LmNvbT6JAT4EEwECACgFAlLXMzcCGwMFCRLMAwAG
CwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEIkj5EKlfhKbDpgIAMiqzRL+DXZf
5O3wPstxaEmZfYtQeBU9Yew4TsWISAtPYQSG8eMYmV0CXrAOE72gBL49mf1ecciG
k0pqvWGhRug6Gl2rnlRMxc2s7T3ttVYuWRr7CesOpxkfP4BFp5VTGU/Wp5obtI8u
Ofo+OdrTax97zATyxhhBwTlmccNDCN/i+kENymf0TNlV3Du7hNjoe52CEQYOhTe1
167VK6pgvWWv1P9cAkUR/bvlpskQYePmGpseOOf+BcGfxrin6by7eNUSu8bWP6tP
wcMjGDhubX4ZtFkA7lWYsHOLs5mMEjmgg+JTBbosM+DmdRuw8IB5NEco3K5BgjlT
+3xS4bfHv7O5AQ0EUtczNwEIALBeOQENyziyaydI6LikwHD2WA7GwpJ986181Kut
wj9PvSjyaR4vD0+e/Tbl/iX+1dLRM2UD9U/vDeac4GvnqmVXJMnftQD4D64A2wTN
ysVSXlNI+L0Yl+V+df7HKIqszmt8easrfgCeh363+++pK5KMDZ1UqAk1sCa8b1D9
Mfrc0u8Gphn/tvzaakAg9T0hGA48UtTfaJbqyMfmjjn+DMzj7+ArbKw3n7BUhKeB
k2D6q5cl3G3DLxGRyjpGUE3ZKitfukwcDp7JcaQ1wCxMRZUAEPxeQ0fyHObADqsk
G17kHFCiVT/wGakTSWozqrpW7FnAhQgPphc2yu/bcwFolX8AEQEAAYkBJQQYAQIA
DwUCUtczNwIbDAUJEswDAAAKCRCJI+RCpX4Sm2p9B/9v58JREsNsUplQsd9o0voj
6NuGfNlNoEWqrULUxksE0EdT8XyjGIQPpFnu6Nz+W3ahsn9TC51DCBvfl96Cxp73
ualGhhCgicoPy56uhn1ONUI5ZUpNdRVak2DiR3D4Oiq9cHxOCS2HfsagQh8N48vZ
0o+CYR1T0juQ+k4uKBvYIP+UhNQWtHJREAZXErH2K9mtWHi2K+WBmAntUgvbCl4N
AsallStnLiwt3UwuuSxqjMjMpiP0OnksixIY6Z+u1IBsw7NI4L0qiHlkFhtzU/5T
xL/1WMA9k6/0GdTbPlDxpZw5zJLpoahKukiSkuHYBmLl/wXsnzaaCuaU4nVLyCqo
=Hnne
-----END PGP PUBLIC KEY BLOCK-----
"""

receiver = """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

lQH+BFKqadkBBADRQcq97jxrBuQ6pld5Dy7ExJnsOXfDXA90qgEmrN+NiwebAxNA
+tH0w74y2AIgk4FZWa0iMfknnrJMoCh/wMJ0wgStOFdB4KUdLcsPnRiFeboxSKNt
+jvF7yKmlaEdf84s8vHzkmhaq/Kz0H9yWFsUJ/CDC1Evq4nDlGUv2EoDVQARAQAB
/gMDAv2KH4uxX8kXYJsipkn5Y05XBVJIheuk4zBDvk3iGh7r2foAd3jcNTQ9oo+x
JSopKBdHpIifkX9mimc5hsKVGJt9sTFn6bjTSmnEqOXR4YyETheSbTxI/Ugwz4xV
PF53KQyhn3y7IX74zXdFSZnjYOwHnHZxKtO3L27WBjp3ylSNohCpxFRs6UV0IBWQ
ptIwyGZKN5M5Fo3diRs0VR/zoAkJ9+yj18xR67UzdPTJ1IjKzbyyvSxqXTwTQjur
ktp31pj7uZnO26ytqL0gGeBkbi5EUgmykgR9KBQe1WyQUIpXN7Qvz8neiaXUu+FZ
Ab47Oa7d/O41IBiFrdyEm2i0ttStuK8BTyhmok3a9CgxZByRa1SGsLxWo2usNWn3
lBzBGIN5PxaNOQJ+isMn5UFqQYHmL/g0E3PwNcv7gOzcM71zYKaUdTXW7Of9R1eR
XySkqyTMylkYx+wxoZoFx6UbHKPpJSGDGVRZZ5tYh82vtDNHYXZpcmlsbyBQcmlu
Y2lwIChwdyBpcyAnYScpIDxnbWFuQHRoZWJsYWNraGFuZC5pbz6IvgQTAQIAKAUC
Uqpp2QIbAwUJEswDAAYLCQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQ7lwS6m4V
25Jx1gQAhsJa1ricgM582fvhBqb4VWQXYHBpVNwitmDhwjPYo1Z3Xl4wLQIFIFtU
T40QqKY5ouUCpvmDdVnAHX+iPpp6/7XWIT2J0RPnTbBAewFhrIsGTsUG8LQjiEfu
QFO6cyKCFFtRrKkCt024rkkWCOVxulHXFeUs0CPemihr5EujuridAf4EUqpp2QEE
ANbfUDuG0HqwnvXPB6XnLJfw1Pl8Pu33Ef9cDZ3DIkU4rONH6HmrUq55M9TOtXvz
W1Bb5Fsc6wUQb32CbcrG7LEWR6ddvWxcswV0DMu8G4eoCNBf2kmIxMIAruiXoN21
v/hw6DxzpQj+CjgNT78CNra5jG6o5bPCtqe0JohqZUTLABEBAAH+AwMC/Yofi7Ff
yRdgH9ZCGwMDKD5sTR3OviO3c3ofKQvYXsPMqtOpQ0HP0U9OgcPtkYwz1tNETah+
Mztm490J17PcAg+qYFTjXHKNZqDfIkAUgx1w9eqV9Km7slGlscEWX6Id+hSFesnF
5dGcQIM1vwH46GTxnX0iYcWrJWuWS/g20DK3XW0yXYvK6gqQdZJYSUizGT2OO08V
dkuIUYzFrSzOjIaO66otAPNSt5Z8YkBkMJBJTI79nOJFdgqTvM1b73LtRsx6eMRH
IrYV6LcP4o/+evU/qDr4Dx16O/S+0urHIc3jHTBAZCpHJ6xmLp9Lhhf1NWu1T4EF
IbSwweER9ZfT/rX/+UzxHw4V9jgwQ6/jH/YRPxLqohRYaPy75fplm9uzlfALLuBJ
JTl65HiN4XI3FuDVXZpW4rXWKPLy11+BxNopaj1UDFwmT9uy4uyKmUcg+tc5K6KX
QVNIxoKBOtSGXSIQv8OOLTt4gEVTq42IpQQYAQIADwUCUqpp2QIbDAUJEswDAAAK
CRDuXBLqbhXbkhCoBACDhf57GrX7Andusgs/wjOLviwGYDRA2dRaTUp1UD3aT+Tu
oD9Y02htJm9bnTYI0fP/dJBEUpSdQIHIYxofS6EjoWvUn6mMOA/dl6VmDQrDWRa+
S+f5fpq6yFTc0e3JlvJuNwFhX+3qbmvMQRcJSxisW+0CMbX9swMtPS3UADbmNw==
=4Gpg
-----END PGP PRIVATE KEY BLOCK-----
"""

passphrase = "a"

#=============================================================================

ring = null

#=============================================================================

exports.init = (T,cb) ->
  ring = new PgpKeyRing()
  await KeyManager.import_from_armored_pgp { raw : receiver }, defer err, km
  T.no_error err
  await km.unlock_pgp { passphrase }, defer err
  T.no_error
  ring.add_key_manager km
  await KeyManager.import_from_armored_pgp { raw : sender }, defer err, km
  T.no_error err
  ring.add_key_manager km
  cb()

#=============================================================================

exports.test_decrypt = (T,cb) ->
  await do_message { keyfetch : ring, armored : message }, defer err, literals
  T.no_error err
  cb()

#=============================================================================
