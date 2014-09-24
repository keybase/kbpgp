
{PgpKeyRing,box,unbox,KeyManager} = require '../..'

#===============================================================================

kms = {}
unlocked = {}

exports.load_key_managers_1 = (T,cb) ->
  for name,key of keys
    await KeyManager.import_from_armored_pgp { armored : key }, T.esc(defer(km), cb, "load key #{name}")
    T.waypoint "loaded key #{name}"
    kms[name] = km
  await kms.scrooge.unlock_pgp { passphrase }, T.esc(defer(), cb, "unlock Scrooge's key")
  unlocked.scrooge = kms.scrooge
  T.waypoint "unlocked Scrooge's key"
  cb()

#===============================================================================

ctext = null

exports.multi_encrypt = (T, cb) ->
  all_kms = (km for name, km of kms)
  await box { msg, sign_with : kms.scrooge, encrypt_for : all_kms }, T.esc(defer(tmp), cb, "encrypt_all")
  ctext = tmp
  cb()

#===============================================================================

exports.decrypt_all = (T,cb) ->
  await KeyManager.import_from_armored_pgp { armored : keys.scrooge }, T.esc(defer(kms.scrooge), cb, "reload scrooge w/ public only")
  for name, km of kms
    keyfetch = new PgpKeyRing {}
    # For verifying
    keyfetch.add_key_manager kms.scrooge

    if (km2 = unlocked[name])? then km = km2
    else
      await km.unlock_pgp { passphrase }, T.esc(defer(), cb, "unlocking key manager for #{name}")
      T.waypoint "unlocked keymanager for #{name} for decryption"
    keyfetch.add_key_manager km

    await unbox { keyfetch, armored : ctext }, T.esc(defer(literals), cb, "decrypt for #{name}")
    T.equal literals[0].toString(), msg, "the right message came back"

    fp1 = literals[0].get_data_signer()?.get_key_manager()?.get_pgp_fingerprint()?.toString("hex")
    fp2 = kms.scrooge.get_pgp_fingerprint().toString("hex")
    T.assert fp2?, "scrooge's fingerprint is known"
    T.equal fp1, fp2, "scrooge signed the needed data"

    T.waypoint "decrypted for #{name}"

  cb()

#===============================================================================

msg = "Please find the hidden treasure."

keys =
  huey : """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQH+BFQiux8BBAC40F2nbvj5jodJPaYHjopzRkbHqxNntDGSrxekul2ztq8TkSqw
tvkpFKcavAmDwbYfiWcdYKhyx8zTfYv4FVJXywc+ByMNM0w1lCRRJEOb/B7C1a4e
de61YkKm1HP/CG6lJ6CMFhdor4hBLFe6EJG+VwdVo+1IUSKQvEjvqlDkMQARAQAB
/gMDAuy40uE2+Ej91nBK33ejNEGCtlRxZVmO2tQs2x7o2NeGQRe0I/6Yhcj+cJM7
5vcSus55u5kN94m26Woe+IllLY5ppA9A/n9QpsZKsnOkLV7RkdDc9oQ1WMb+WJq+
CBouRHZ/SKZut7R/Q3LX2sctcjDp68a4cRnA3RrPlD1/922vra6e5c/LY5dMLfk3
WtOhEA8DYHfVC5n/Tb/ylaF3d6OsvKOzam9nLUyKkOrJKFoWIj01k9yYs0KKnsxv
VuYLu1v+/MBihKLsopLgUeLjYhgofXvD7XUWqr9e/XEv8QPSD5DssfFGVaXvbwpv
SHP/j43kwKJ1rTIbgv28VzPPcSgs9QKAoboFTYn9j6AiDBLUSX/mm6PUELs2kZSF
qq08NYVPynnbd3tmEeq2nv6M/V1IiQrkrKRZ8hNQb7xgkSxyiDnEpZKlsrvKWbWk
NrUWbba2xxuMa/MRrRXjDMNI0z25mDewuw+Q5knyzZu5tBlIdWV5IER1Y2sgPGh1
ZXlAZHVjay5jb20+iLgEEwEKACIFAlQiux8CGwMGCwkIBwMCBhUIAgkKCwQWAgMB
Ah4BAheAAAoJEH/f0cCz9hwgYJcD/jiFThnZn65rRt25b+WQ60H2PXRsFRk7xOhI
cJb7rqYUfKhKWHZk1Xn3kQaG0dpgSFQmCXuKbZ3uusO9TETLZQ1+Nwk5khtEbzlR
NDbTDVVC9CNvXYVks55SYd7BfOZZnWLkfCCSG9wQrS7Mp6gsRKiztB0/fgxBe2yh
cncKyFFGnQH+BFQiux8BBACyZciK6nWi1+y/KvwyxA/wEmWv09wpTehw2PsGKmK/
XCejvM/bwKD4eVDFELuTiM+oWmA2zdha0uR9An8+dSmqBS9a8bgH22O2prHYOCBC
AesY+WnQG3XCVCS4rXyeHxdWX/iL3xrk4ZKF/bIaMjISnu8RuS5N47hk6Fvsk4/J
xwARAQAB/gMDAuy40uE2+Ej91mV5S6k0jBXaYV9GgfvsCcFnnDFXnPb5B+VO/2cX
gPnABGDSQriSqOznOPkFU4m+v9WooHqdOsgQw/5plgMFHyW2+qvay9pzd/zOcEzS
WK+c+rD17yttiVOhrw/FcfeqHT873WEuvmXQSvCA8lKPdqUBaG9ApT+OoUh7GIbi
B1vvEn3Jf92cTbzcVa7+E74db4/VyVE1ButlfpuHjYd+tqxfrTXIYHOqMJBd0Jn1
S4zn/TleF8gkZE5Q48ILZptP+T6EsegZzBfLoHoVAjfuX50O7C5CjuCpHlEfjzEY
EFmHupGnI6Zl34FDd0ZwLCB+27cpT90fxtIn5ot8/5eiKLyBgdJc9uGSTVHNO/Rb
yYdkMsNAmOpPfIw9UtxJB03ECQVBHuZbqAlUDv5+xguCJWjePJ4T5V0KVm5goSBj
u+aJpkTmrouRv1BEKXdxoRJy0yIgJFs6hyBp7Zm9b/INXTTG+jQUiJ8EGAEKAAkF
AlQiux8CGwwACgkQf9/RwLP2HCCGlAP+IAsSgf/HrNSnBopC2pR2j8fM+7E0UF3F
hlLRqm3wrCjsN/pQRDyKKPLnG+MQbG6aCvY93Pw6Wtwf4p2yTWCiHrU3fvf1daFu
bNjtii8nMMOHaOD0oq6HK52j4lqjJJsleD15NAXHPlQcFR1J7JSk2jh0cy4zoZ+F
khSIdcmH5YA=
=zcv9
-----END PGP PRIVATE KEY BLOCK-----"""
  louie : """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQH+BFQiu0EBBADoCs6TCxvDuPDcvrC7ZPuizdDOthYd3KknfJpyyDpbcmY3F6p1
facRh7GOq1z9sUmwv1P0qSA1c5FsjH4uGG2EtixBOEQkpbQqx+H+o1yNJuedZDrn
DpGb7l8DdY1CIEYostL7XLVSaq1l+yBCkWEZXyk37hywD2hD86dxfCuteQARAQAB
/gMDApTDdTwi/SrB1rDHF8nq0HeWY85TRm6plilWILDX68H6KaJiQD4VQGcgYAEj
FCv+CR3C3EToN3wDDa3dsU2pmp8XTlASY7LYi4RUdQiFvVKxaVNZPhA+yJFnTzXu
8LplTrYAYzJmQQPGLCw73peVwMARsDdnJPYqZIUGA//xW+zU849MdNJGD2ef9CSB
VnoOmXGgsQEzs7Xw3qJ4tj7VPzhz/PeKYxdlqjQ7qH2HHUtkJ9GND+n+v7hz7T23
1Ejkrr9fZ+Jvhd2gY/gJtEkFILTWDmges0Eu/LvVpohI2Tby11WNBBzQLSh/6uKM
pVokRw0gKyXjLDrq7t/dHjB9spxxxEGcJ/ATU7BOoSASMCwfi/u2atXuXwGy1unZ
4ZwIfUn6bl1sA5TrKc+ZbE5cyWNQDDaReCFjzLWoZkDwS4MZnxYGRVHiuKgvJ1bu
RIvhvghx/NoYBmwhp0lPqj95RatgBOzYj2QpP1lIZ+6ztBtMb3VpZSBEdWNrIDxs
b3VpZUBkdWNrLmNvbT6IuAQTAQoAIgUCVCK7QQIbAwYLCQgHAwIGFQgCCQoLBBYC
AwECHgECF4AACgkQzCmBbOQ4d5WmjgQAlXPt3XjoGsFo8Qawr2gA/Ikeku2HRC0J
YCQq9Ydmffz9eg6z5d8F9IHKSzahlfLcaOizcW1L2EI3SJyYwrL28JYsQT1aDSMK
1fZO4nP1G9Z2a6hSGilCVEQgsE2M5nJ/EEg4T75HmOv9sfYYKIejs6cZPer33OZs
WqPlFkCnKwmdAf4EVCK7QQEEAJ5J05w102lve6btFCjn66y6SWRpgteqvyuKDtBR
2fzbT9rNLlLp+f7tTNJcnRfEQ9OWwIHrUcrdcoJQ9syyviUdXDEKOYCSvcBsNY5P
T3y/Lf5qbE+c0o2qBy+uoNQdU6bEyDWbzrUiER7xB+mI2EVIblSkeL3gSTDN4UJ1
YbH5ABEBAAH+AwMClMN1PCL9KsHWPjw+wY5RwuCXbLvLH9lUWUPUKDAFX/p7N6m6
EkfszFNRpqBcA2jp8mokCTE3X77EIekFvIBrcboEb71tFagIVENAUV4fhP55zz5W
8YDajHGtQOVeA00r36jn/ZjqM31szYRgoLLfK7eYezLzOZEKrWNKpVfYvx4eZdR8
xDPqGLcg1C37UJ9HnssAyiTv6vx33yHn679IYA7j9xcuGqe1qi80tpayKQhk1qN7
UKv3rjlV6ujVKhKesMB9FjmWQ1SZc+fwDTh4NG/dnBvNldafcBbinx55xYA8bcd0
5Plq+baNqc3Dh/V76/8HxH/iLSWWpBPmCrbAiOA/j3dJtY0QCbEkOKxGbNnnlDuP
MNCv6X7qrRAyyY3/CMB5HBRz2ZO1UpSA9y6zeQFtZAa/oNWug08DoTtxXSi4xZBX
H+WV7+/pXVtsCK9+NUm0clTzO7ZbcgNfQGFYb4aQJux00PAoNKfBGUqInwQYAQoA
CQUCVCK7QQIbDAAKCRDMKYFs5Dh3lS4+A/9kRrajjO5sOwZUbtyh1PNXd+DBnMKX
tIjjX59zoFpcUKRvfFqsWjcVxSUtMNiVaaNBj2besBT5qPi/1quOPJWe3orDjdnX
2g0gDE2pco+Ulwx0SUCmTA8cYwprcfheBYg1bC4humOWbXKCk2turiCeFHX0SYap
Cpm1iLp8s5Uqwg==
=E9Uh
-----END PGP PRIVATE KEY BLOCK-----
"""
  dewey : """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQH+BFQiu10BBADod/6GZH5nSysrTL87mGU1ymZpP/2ax9HA8+4Q5JiEFQJHc60+
24LOnAu5Du/hJKwAkgbXaFCi/U6GOUF5HR7oUom+mw1QULH9ZLraMXwQDiO+gkeE
tlFyRMWkgZZoMAGrNeCrUSkns/6v+jsJqEnPGPf+fDBaYC6zPJlKxcBH9wARAQAB
/gMDAhP36FUDs+J01tpCQFZU4cDbkLPDwY/obD2yCgGn/ZzUq393SiX+IwqzI3rS
Fnjvv+/P0M0HawC77jPUf4oYBcZ8M9rHbL0Nl4WZpLEzqAYaiwgd/ZEg3cA6BuYh
TWirowqLmpmS3qZ7bRYbcbF9NF4O8cebqPhKK3ZVErcpBsWbsTHkz4qQsPDnxon9
NGP/3aJfns3r1aGbagzgt2HskPrwLZ2/Q9+sLP+yZucTqsYfnkkvjVL+heNexAc7
dKwpUwgybkybvTIhwsbUHuL/pTvM6t1C4d+BEvV3HVnfBtRM66YDXy+76+o8+NQk
PwMjut6Cgw0F8SFbYK+LJnYE6N3W1EnGWbR7z2+BODgSGo0OvGEjqQTYdzKE7GLe
Q6Vpz+Y7Ge6QbEWPqixe1/XPtsq74ijCmusAm0DXOEYH73cZl1jNAWiU9NLZblkD
0nTYscJtUvL2TjNU6MWtSdta1AQ00KP7BtdrTvbuJYoMtBtEZXdleSBEdWNrIDxk
ZXdleUBkdWNrLmNvbT6IuAQTAQoAIgUCVCK7XQIbAwYLCQgHAwIGFQgCCQoLBBYC
AwECHgECF4AACgkQCr7aAiHTjfshQgP6AkHgbUzVFn7lOD8AWvN8h7+NCLaKbn1d
laU7ZU5qstuy9hHuCT6QOHhflEqKJ2FzyDEwJRVOeMKG9mDxSWRNr68aw9CLGnj8
fO7ScQXk1Ku3AI0hENgjRssNuxly2zfhyAh92LkqiQI2R5SXSMIKWQ9JbirHp6dY
ZwKvtZuGK6OdAf4EVCK7XQEEALsA4wmIRB20wr4p15LXkFHYOeMLPSkvku3VvzIY
3EAt7V27SjpPE3J5NcKw+540MtnNPWVsiuayNZDg5b+zFyZ+tYam9gcYjIkE1ei1
hO3UEXcIW6hee5k4ewxpXiQfkz17RBpI44AvTJpM5M/xCvaTMtRwEKLFhjcWhJbP
aCfxABEBAAH+AwMCE/foVQOz4nTW9QwkOvrv6IjZ/iItEGyk1fUqkocC+ItOF1ZP
/FRTwEoVVLRDqZjGT5ZvoKRh/FLZzjmeUlVDdKF3Jmlil9TAtAYlGyBJtLHbQdT2
9D8eiSpSw4MDJu/vxTnTWqKuPceF0F1lnX5q5R2NpzbyWh0gd7em0rlOlCDz1mcS
KJesFrKct40f3Yef43ZEnUBgnDfBHfL1DrU1gfO+vPtFnVNpWgFYm/Drn82loRQ3
sAj9TYZibZGhL7lGMv2XvSJTyzZalMmtIQsMUDb9kP7fqBjLeTNdPQYyvA+boP+8
KKNUFSJ+T6Q75qn/isacEtpuUQkL9xm6UylLj8Y430d0gIZ+fIyJlM1IPUzvX/Uj
ISbFkyLEQNYVq7ENS+3bLJIlR55d3kDera437H/ZXUTbeh5QAzL+QTcbo4S/MDMz
jGMg6vgfksrxK0wyQU9pevgTO/DTRng3mW4MCZNI3O2tCfEXIbpr74WInwQYAQoA
CQUCVCK7XQIbDAAKCRAKvtoCIdON+0uqA/4vr3AyfXftFn7CIR+gNLibYNDS4BN6
03js5q1EeFJysJNd7kiWsP2wbfYWCO11EUQNXlNnfKys9J/ZaROpZ2ikI8XBwU2v
ZGL35KU3Q+VbGtn9nyppA1bF/ZNaTacr+QhaUYvmq5ZxndkdMPgPi4vtehh2HvUR
T5xqFsrwJ2EPLw==
=QEzn
-----END PGP PRIVATE KEY BLOCK-----
"""
  scrooge : """
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG/MacGPG2 v2.0.22 (Darwin)
Comment: GPGTools - https://gpgtools.org

lQH+BFQiu3UBBADnPKVZZbkw7ocBgekLbYARgQiX8gTcs54dTOMNAd3Tr9b6ep5+
Q/t/Eh+2FxhzkXjPgEXAuHaMqf3BhGqjzF11zam6+9bm390GQlxmxpdBt5WmxtTT
KmNtLBZL6Nnxx1LUBN75BLhcoiGLhpbg33R9bKOWJ2JTjHE0fYLULhjOlQARAQAB
/gMDApp3S4hoFAVx1lkh1LrF/iwrPc3jBHyA2FnP3b6nTYkfcZw7ayNIOyhFvaJa
ENM+JomkPL/MgEECfczt+9hz062AjQo62h3pTp4dsiyy50IYfQlFM1auFgfgS8KN
P3wqgUt6jNpHfoYIIO0Ba8dI20b+fW0aLJau/4W4C07z/w26+X/WcMZORKBHKZL2
pqBnX6uRweC40ZDdpn5z0UQSjUOmLXzG09b30Jy+jUIYa3BII/O/NyhnNHAaJyaG
DrngvPGK0Yen3xA8t9MmY5u3gsusOMKPZCnUyArSTq5TUae+xcauBvppnRHMxYie
DCEEqj3CmKAJub9BToIUEj9LPFMY54JTkjYvRkQN7zMXY+0TqNmXk3NJfro451dD
UBkjs1Y7A/Ng6vZsk2o7Y6ZtOFr0o4c1qFnWpPnlMBVSrbSaFwLdTxknJU2AD1en
vrbwqzqKf1/l6VulkTBBMDkdBA6aOcFuvQEmWa+vXAy3tCBVbmNsZSBTY3Jvb2dl
IDxzY3Jvb2dlQGR1Y2suY29tPoi4BBMBCgAiBQJUIrt1AhsDBgsJCAcDAgYVCAIJ
CgsEFgIDAQIeAQIXgAAKCRA8TPwgA+aadQ/0BACDGuh/OPakGL6hElpI8dwouTpF
hJ20ykZCNLFoPbB842wCVWkBxTp4giiIgbJSgfMUq2HfYLxdXcwywPjYaKPHrkI3
KA5gARHmOcyBb8ZoRwEX2Q4SqljSqmdU8q46HRTFAnYpu25M/E6CNju4KIijm3vg
64MI6xWtujn4zHsKUZ0B/gRUIrt1AQQAzC97DAlQhixT3haJUCYA6fJiKPe6Bw3A
bNvkP7vaMQKnvGtxXRfOiTRxWUMqq+VDWSzYQQweWt4c9jE1NPdhjfNTDS50mjRb
qqHAn+A7ZgvOLBxx3jmdR1gF3yC4hvVb7k6vdrwVbi6B6ljZ49LZ9LzoCvrhto/h
BzwdwIXz8vUAEQEAAf4DAwKad0uIaBQFcdbFD+47Oe1WGWq+aKy8pb3ynGz/Xg3y
qhGNk7BfNGKoOqYZ3qgZb7YVzUamuZHJbuf1bWJ5qr1ZhGersPEfSIjrOBm2NEa0
RZtwe8YVFpSzIz8sQVbLraF/WbXImal4i9n/fwDDh4MquwXZi01b82YFZzGyk7M/
dqvrBnmZO4n0dh5mvh2iXg8fr3dcKds2NVsFJVMR5xKwXpnUrewRIfIrBuFWVcxj
mWMkZHnqKZliYxxm2huvvkLigoccUoEjd+dlu+Ajx81ZDuy9pZjwkWV+9S9kol8j
HvBqF3A1WqFPLUsTNenJ6Som1Arv90sYMdZljnkWI4sd5GTYZ0bU4Dkg3ew6+Tru
qXKpCWhyd57KqLT54R+SM3GtwqJlnjOtXO+ZGrXewYI1IlLeufsETu5emHDfljZ3
V1q3NelrGu4AxWoR3Qvi1hPXkhNpW1Z1o63gBLZSGqIPrl6meaFmoz0BChX2LIif
BBgBCgAJBQJUIrt1AhsMAAoJEDxM/CAD5pp18RMEALkVWQFlYfuk3nfXcK3pTIjI
GVIrn+nFTMsaiMJ/ubnGZ1AfgOSWhpbzotTASOzBfrXrtXGSiONCMp/T2u2CDMLD
dU4xsgqComGHegwMgOIFMLSdCusCg2wUHVW+BENFapAys2wxduD9K0nE0YmNweSb
8wOr9q+0/tgtlBF2Ec7E
=Lrk6
-----END PGP PRIVATE KEY BLOCK-----
"""

passphrase =  "asdf"


