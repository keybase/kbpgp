
{parse} = require '../../lib/openpgp/parser'
armor = require '../../lib/openpgp/armor'
C = require '../../lib/const'
{do_message,Message} = require '../../lib/openpgp/processor'
util = require 'util'
{katch,ASP} = require '../../lib/util'
{KeyManager} = require '../../'
{import_key_pgp} = require '../../lib/symmetric'
{decrypt} = require '../../lib/openpgp/ocfb'
{PgpKeyRing} = require '../../lib/keyring'

data = {
  msgs : [
    """-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.20 (Darwin)
Comment: GPGTools - http://gpgtools.org

hQEMA+bZw3a+syp5AQgAqqimwGjRe/m9d74f2Itu4rAs/BJUjgPprCSn1JTOBurK
nneix4XLQM9slGNJANiOhjEmGR011+Dhk4PV2SNaJrgXI0RS43O3UAjI4gHUHpKF
lHit1/UBwK24dTzl8G8LSBoI9g1p3QZTZqszsrsYOZfzpoObE1If0IlYvP6VTURC
QUsHoOKaWXbVQFaUqW8tYqpCgiBZ3BLQbzdO8Wy20R3qRr/zEltvK62o4fitW1j/
t8vjzKXHxKCcE+Rqwdn+qb1/KLf+AOrqGJL8gDXytVeQlxMmiV3J/GDgaq/Ikjzk
whot7+b4kLwypxB8/fqNO2alFICwnXtlUMeqwtJFT9LqATfV9f85EEfr3Q4ejsB9
1eMHkubjSbj/SMIw+HlA/dYo4SFVxbej1ur3eY+VQFNA43IqSSsTKp2o9ZEvyXOt
zOHZSscVSPg1h7huqi9LWgAYUzPTqQHYkzRs7ckJ/jb+LBKesX4n6yUhuO0XZzNi
EC1qNueJjkNOy0T+NCSuTdMYq3P8De0hBu/5HnrUwgsujgWrrUMmSaTmCezyUkSo
4tBaPu8PtWaC97TPYefTCu5eI5L28NAAlrGVxtxkdWJs2IJZqGDR0O6X+xzxkFsH
jc1chiypfpEa4XsuvqfAkdU0I036ebwo+65lQwiVnbf0+XKxup3QspI9lmlMoKL3
A6Th+sqaLEv4GOca1YyI40on6ESg24TaC4WQK+SIVTuYqNdWvhb2lCcdK/WdzkIw
Jwiv2OGfAh5S8yg8c6r1k/WoWv1/hK6wj+MhBX7QSAtkde5BYX3P0ZpAUYXIBqZz
TscMwNiHdgS1FcQGk105wbfztfpBLAkIlVD3PmHxE8rIhvAcS+1GFn+TYSwbZE3M
kYyFvOKHjwnQEdQCSQuPc4YgfWChFYBtE6TNvp/e4rhcIf+7U6uRKLkXSS80jzDM
9sRp11/CxDXx4nZPF9zXd9sKBLXcsEs0QTpxwAzU0GCj9jc8AOZTQXFolzal40S9
C4HoctsmAb2ybX9+4E0SvcBGoMpmWDdXH3KB4MfJoSFLP2ErdGGuIIlDf94oqprv
sNOCls/STmI9L3RR1/g9AuwIElm0HKa3YIzJHE8hgMjsOAvDM1VQqRBLoYbKI74w
bLwXTajt2kN4gdJgHHZ0dZjZQZlf5D7DukY7qdghOOOOxrbPgrN1Qy8QLvdDcio7
lRe/HZUJkihmw4YfMaYfR5c0tVjfPVB/le14iz5E8gLFbWq0tANgEX5h8ylUepu/
N8eJSajVl+ybJtl+YmijM2viR03BJjnyWQLcTk+ZXqH30ti7cGFqtBrnLuIIn8sV
m1U9CgicfSMzg/ASflw6U6Zb290uheY1rFte1ZfrKoIBjGIV07s243VDR1I464zj
6xqr6dX7IuC0iP4BcdLEAUe2r99s5dVcuccHrgq7Me7tTYWSyxEbGfw2N1H00kGb
uOftACanYOkJT6j1m3k1c7XohZsOL43JK3yOkprGZczHRwrrQrbdHHXB27PhVq8e
YyjPQTmufZtWXgkdv1Q4f/oJks7NK9RATBfD/7qgOYpWNDDkmFX9qK23HA4shJu+
YnS6s8MBxyb+3HSkqL2z1Vv5JjEDpeuVFtUsJ4dr3BO0MzrqHVPRDJsjiIPqyb2A
bXX1zefINu0l1zgnDW0lggN/Fxqyrw7654yQGR1uRyEAVMO3QeoWaBSMIf39XiRN
YcDJo56SFcZQovBMuz6YzddJNal5/BFAdWhkEbwzkqJa3QEjm69YwQem9+ZB2n4I
RsLjWln6APXtNeTi4YAXgcb7KifnLSvprwGcna+H0b4UJVfs3IXYjvi1bggTGTj+
1rWAX2+f+fis8i40nH+zHQznZKtwZ/s7qb0KlwNui3moXSOd3YVSNwgmDMAPlPun
B5A13/wvLDwXP7j3gUZ2MJcm3x6VrX1LTcCRu/AqJFLyKHqovCeYSdGRotFRNDzv
NHw3ZbXgcyHyOtSoepHh+idb+F02oIDRkjQwezPRAiZk/vFbjAXGCcYQ9UBmScLM
QJlOr7Ua+tqT2rKmb1PwJYQz39SnUDdUD2+7VckUH/ioCL16k2x0XaK9KfSIpmzh
Qwe+4+nd17Jpj5jFfg2mYr5ccDIEugfCcplExI/VcgS+drlFSMgP871rzeJyIpCy
mqG0bSbMM3VJ307AWDqoiP2hSW5wZ9YweVeFh1DdH2I2Xwt5xYkQDx27M/H9LO1A
WYxrooYFv+qVvVMS
=euQN
-----END PGP MESSAGE-----""",
  """-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

hQEMA+bZw3a+syp5AQf6ArI5PQg+kzq4h7T4nZA9q/Li4kjf7eN2C4m1XuBm/B08
245kUmI5iOkfFe9HbT3azrvdNYe9VzFweoKKJkWbYLRQsw8BN4lGlixpETDle4cz
bd94yIbs//Xe+505h7jU+RY+cAqamaSPTpZG901dIB5XJwdP8qM2mYacCeBXIWmE
BMUYUT9MtYZFESstbMHI/pKUiJRhhBpJLO0FP5KdGyuO9JOQZui0cagnxUynqVTU
+/DOMNf3nQeXBM4lyZQx3pFcXzNwL6URXz/yRa25CxDP4bpVcrZ5qSiJqZ+jpSRs
F8WKEkGCftzwsWIxsUPcs+6ClBruLbSKSroP4+ci/dLBDgHoMF+R6Efj5sU8tWlE
1Z3KQjB2ENqu7XIKf49cpnY06K3QKWppexflWT5UbHzOwn5O9Ih1NPL3PbFqQV+/
yJDO2qjxvq6PXOOwRbxvasYzpYXoLO5soyoEbmQ/VwTZL8Pw0Gima1s1GejTHcvv
Z3BvqyuiJGAnYq5ShI+SlDVI2uRwJ6nThQtGdIjaQZo3ilSPuFE8sWSO03IKKxQy
ZyNwKj0miHaIOqevu88588zwsAKAxUw7gYd0GWSN9G6MHf6P1P7dZyd92dPnBJu0
L8AFMrYN1HcLuLG12BeONPUty4ZGUwjnFn9wu83RRKZ0d+yjVzhoAv7VbQxKBE/p
eQntRg76DYwOmTBV+ZGsO+rezxQ/1sEMRq0bvJIybpDLFUwg3QmGc4ZGJyBQ/FKA
V7xwSJBg5wSzZ9pSo4HQFi6pF/UPTc9xbbKQDIEnZlYdaIiTS0J/Xx321f5Paicw
wa/vt7tlsS8evxmVvhgMWZ0tc8B82ZM8o1AHLewmty2PFPuGVMG9W3DJJSBH+fRC
7jB2iHwfhUQ5ntFkxMcmVY1IYK2WtHQ4nzYdvhiSp9MTuBqXfy1RzWq6LAbUUGfU
o7cJyIX4q4MjzvkYEjxxnw==
=S4AK
-----END PGP MESSAGE-----
  """,
  """-----BEGIN PGP MESSAGE-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

owGbwMvMwMSo/0DG1dnjliXj6ZdJDEFZhebVXAoKSnmJualKVgowoJSdVJBeoKQD
kkpJLU4uyiwoyczPA6lQ8k6tTEosTlUvVghwD1DwzC3ISc1NzStJBCsA68hOrSzP
L0ophhoYrZRcVFlQkq+ko6AENhWsAmSGkkIsWENiaUlGfhHcfiXfxIry1JwcBe+i
/AyomWWpRcVQF4CVGOgZ6BlCpHIyk1PzilPh1oE8BBQuqSxIRTLSMwSsGsgsLcpB
eFVJCShYC3FGbmJmnpICQkpPPyczSR8kqpdVDA2MzKLU5JL8okygdQpApVC7gOpA
GsE0yDyw2oz83NSCxHSYI5QySkoKrPT10zNLMkqT9JLzc/WhwaCPFNpJpenFyBEB
0lSMR5d+ZnFxaSrUdUWpBfnFmUDnVYKNQA0IJaARqEFw4B5IDI/heiAtcP+kpBak
5qWk5iWDPQ/3e0Ep0NrE5GxwANjZGiJrKHPBriepKL+8OLUoM60SrEsL5q7k/Jz8
omJUMWDspuiWpBaXQC0Axbw5TLIEmDJzUotTk8GSMMcjRKHKkvJQ5JPyUAxPzk9L
S03VhSRzVMvzgek+N7MYTTQlNbVAN7WwNDEH3anFGF4C25BaVARM3wj3m8Fkq4Ap
RhcjNEAhyFXL1ckkw8LAyMTAxsoEyqgMXJwCsNzLsIf/v8vd8sUme3UElO58Zrko
lcM7/0fuk6KiE15KcfZr7Sau0+44GZAguGBXYFeH/Q5lwcXFfzb9PnFF10l5V1LX
PnZVni9PZ/74785esCHmTmGTcerPta9fnSnTtDad+HlDe379gx2ONu/9Poaavn0S
9TBA5WT869nvTx2JXJrqb11X3loi+eKkUq5eJj/3A8Ng27gkCb6WFUo9firKEXvy
tA6d4Sr+Hjz1qJDjyi2Or+te337+onL+2puytjwr9uebnZx+bl/jrIe3xbYo/Vz8
MKht7nndOYc8St/t3bLghWHn/tz4cz2GUR6LV+/d++7MdeXjWldb+59xVb2azVMb
4MrV23v89ZpY5ZMLzDe+s9J5uXvn0hl3jE1yVO2yrgXOK88RTsi2/r02Y7/PfIa1
uxXme4gyeVUEZ2/tfzP3bFRKhYRSzytdLeMyswvXbuw23t8vZ5Cd1fgptEEqTz1u
bZjQoZViEVEa986Vv98wiW+eQsikYoNXl/Qt9oRHTvkxOaE+a6FxoHjr7YJz1iEP
7n719BOuS+nkkeqPPT93AQvvwxK7PydyUi4YdO4XkExRZPY8uznL10ilmOfaXfcm
ZubtJlEMmxiKY7nanMukz9XoaGyU0vUKyfdSlKlatkmLpeMF38Sdq6zumce8n77Z
+2alsv4GBtmYKYsloiQbrW/a2dwQn2TzWlzkmOXLOuOzDVUiyx3T86q6DQA=
=kOKo
-----END PGP MESSAGE-----"""],
  keys : {
    decryption: {
      passphrase : "catsdogs",
      key : """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.20 (Darwin)
Comment: GPGTools - http://gpgtools.org

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
ObMKV7f7yqGEQNpyrXlHl4qGSzkvgxQ6IzTA1g==
=DRiu
-----END PGP PRIVATE KEY BLOCK-----"""
    },
    verify : {
      key : """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - http://gpgtools.org

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
nMd8vYZjDx7ro+5buf2cPmeiYlJdKQ==
=UGvW
-----END PGP PUBLIC KEY BLOCK-----
"""
    }
  }
}

#===============================================================

load_keyring = (T,cb) ->
  ring = new PgpKeyRing()
  asp = new ASP {}
  await KeyManager.import_from_armored_pgp { raw : data.keys.decryption.key, asp }, defer err, dkm
  T.no_error err
  T.waypoint "imported decryption key"
  await dkm.unlock_pgp { passphrase : data.keys.decryption.passphrase }, defer err
  T.no_error err
  T.waypoint "unlocked decryption key"
  await KeyManager.import_from_armored_pgp { raw : data.keys.verify.key, asp }, defer err, vkm
  T.no_error err
  T.waypoint "imported verification key"
  ring.add_key_manager vkm
  ring.add_key_manager dkm
  cb ring

#===============================================================

ring = null
exports.init = (T,cb) ->
  await load_keyring T, defer tmp
  ring = tmp
  cb()

#===============================================================

exports.run_test_msg_0 = (T, cb) ->
  [err,msg] = armor.decode data.msgs[0]
  T.no_error err
  T.equal msg.type, C.openpgp.message_types.generic, "Got a generic message type"
  [err, packets] = parse msg.body
  T.no_error err
  T.waypoint "parsed incoming message"
  await load_keyring T, defer ring
  dkey = ring.lookup packets[0].key_id
  T.assert dkey?, "found the right decryption key"
  await dkey.key.decrypt_and_unpad packets[0].ekey, {}, defer err, sesskey
  T.no_error err
  T.waypoint "decrypted the session key"
  cipher = import_key_pgp sesskey
  await decrypt { cipher, ciphertext : packets[1].ciphertext }, defer err, pt
  T.no_error err
  T.waypoint "decrypted the message using the session key"
  [err, packets] = parse pt
  T.no_error err
  T.waypoint "parsed the decrypted message body"
  await packets[0].inflate defer err, res
  T.no_error err
  T.waypoint "inflated the compressed message body"
  [err, packets] = parse res
  T.no_error err
  T.waypoint "parsed the inflated message body"
  vkey = ring.lookup packets[0].key_id
  T.assert vkey?, "found the right verification key"
  packets[2].key = vkey.key
  await packets[2].verify [ packets[1] ], defer err
  T.no_error err
  T.waypoint "signature verified properly"
  ind = packets[1].toString().indexOf 'Buffer "cats1122", "utf8"'
  T.assert (ind > 0), "found some text we expected"
  cb()

#===============================================================

exports.process_msg_0 = (T,cb) ->
  [err,msg] = armor.decode data.msgs[0]
  T.no_error err
  T.equal msg.type, C.openpgp.message_types.generic, "Got a generic message type"
  proc = new Message { keyfetch : ring }
  await proc.parse_and_process msg, defer err, literals
  T.no_error err
  ind = literals[0].toString().indexOf 'Buffer "cats1122", "utf8"'
  T.assert (ind > 0), "found some text we expected"
  T.assert literals[0].get_data_signer(), "was signed"
  cb()

#===============================================================

exports.process_msg_1 = (T,cb) ->
  [err,msg] = armor.decode data.msgs[1]
  T.no_error err
  T.equal msg.type, C.openpgp.message_types.generic, "Got a generic message type"
  proc = new Message { keyfetch : ring }
  await proc.parse_and_process msg, defer err, literals
  T.no_error err
  ind = literals[0].toString().indexOf '"devDependencies" : {'
  T.assert (ind > 0), "found some text we expected"
  T.assert not literals[0].get_data_signer(), "was not signed"
  cb()

#===============================================================

exports.process_msg_2 = (T,cb) ->
  [err,msg] = armor.decode data.msgs[2]
  T.no_error err
  T.equal msg.type, C.openpgp.message_types.generic, "Got a generic message type"
  proc = new Message { keyfetch : ring }
  await proc.parse_and_process msg, defer err, literals
  T.no_error err
  ind = literals[0].toString().indexOf '"devDependencies" : {'
  T.assert (ind > 0), "found some text we expected"
  T.assert literals[0].get_data_signer(), "was signed"
  cb()

#===============================================================

exports.process_msg_3 = (T,cb) ->
  await do_message { armored : data.msgs[2] , keyfetch : ring }, defer err, literals
  T.no_error err
  ind = literals[0].toString().indexOf '"devDependencies" : {'
  T.assert (ind > 0), "found some text we expected"
  T.assert literals[0].get_data_signer(), "was signed"
  cb()

#===============================================================
