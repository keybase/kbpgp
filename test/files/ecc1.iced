
{curves} = require('../../lib/main').ecc
{Point} = require 'keybase-ecurve'
{H,nist_p521} = curves

# http://www.nsa.gov/ia/_files/nist-routines.pdf

#===============================================================================================

# Section 4.5.2
exports.p521_test = (test,cb) ->
  C = nist_p521()

  #-----------------------

  # Compute R = S + T
  S = Point.fromAffine( C,
    H('000001d5 c693f66c 08ed03ad 0f031f93 7443458f 601fd098 d3d0227b 4bf62873 af50740b 0bb84aa1 57fc847b cf8dc16a 8b2b8bfd 8e2d0a7d 39af04b0 89930ef6 dad5c1b4'),
    H('00000144 b7770963 c63a3924 8865ff36 b074151e ac33549b 224af5c8 664c5401 2b818ed0 37b2b7c1 a63ac89e baa11e07 db89fcee 5b556e49 764ee3fa 66ea7ae6 1ac01823') 
  ) 
  test.assert C.isOnCurve S, "S is on C"
  T = Point.fromAffine( C,
    H('000000f4 11f2ac2e b971a267 b80297ba 67c322db a4bb21ce c8b70073 bf88fc1c a5fde3ba 09e5df6d 39acb2c0 762c03d7 bc224a3e 197feaf7 60d63240 06fe3be9 a548c7d5'),
    H('000001fd f842769c 707c93c6 30df6d02 eff399a0 6f1b36fb 9684f0b3 73ed0648 89629abb 92b1ae32 8fdb4553 42683849 43f0e922 2afe0325 9b32274d 35d1b958 4c65e305')
  )    
  test.assert C.isOnCurve T, "T is on C"
  bad = Point.fromAffine( C,
    H('000000f4 11f2ac2e b971a267 b80297ba 67c322db a4bb21ce c8b70073 bf88fc1c a5fde3ba 09e5df6d 39acb2c0 762c03d7 bc224a3e 197feaf7 60d63240 06fe3be9 a548c7d5'),
    H('000001fd f842769c 707c93c6 30df6d02 eff399a0 6f1b36fb 9684f0b3 73ed0648 89629abb 92b1ae32 8fdb4553 42683849 43f0e922 2afe0325 9b32274d 35d1b958 4c65e405')
  )    
  test.assert not C.isOnCurve bad, "baddie isn't on the curve (off-by-one digit)"
  R = Point.fromAffine( C,
    H('00000126 4ae115ba 9cbc2ee5 6e6f0059 e24b52c8 04632160 2c59a339 cfb757c8 9a59c358 a9a8e1f8 6d384b3f 3b255ea3 f73670c6 dc9f45d4 6b6a196d c37bbe0f 6b2dd9e9'),
    H('00000062 a9c72b8f 9f88a271 690bfa01 7a6466c3 1b9cadc2 fc544744 aeb81707 2349cfdd c5ad0e81 b03f1897 bd9c8c6e fbdf6823 7dc3bb00 445979fb 373b20c9 a967ac55')
  )
  test.assert C.isOnCurve R, "R is on C"
  R2 = S.add(T)
  test.assert R2.equals(R), "S+T = R"
  R3 = T.add(S)
  test.assert R3.equals(R), "T+R = R"
  test.waypoint("addition S+T")

  #-----------------------
  # Compute R = S - T

  R = Point.fromAffine( C,
    H('00000129 2cb58b17 95ba4770 63fef7cd 22e42c20 f57ae94c eaad86e0 d21ff229 18b0dd3b 076d63be 253de24b c20c6da2 90fa54d8 3771a225 deecf914 9f79a8e6 14c3c4cd'),
    H('00000169 5e3821e7 2c7cacaa dcf62909 cd83463a 21c6d033 93c527c6 43b36239 c46af117 ab7c7ad1 9a4c8cf0 ae95ed51 72988546 1aa2ce27 00a6365b ca3733d2 920b2267')
  )
  R2 = S.add(T.negate())
  test.assert R2.equals(R), "S-T = R"
  test.waypoint("subtraction S-T")

  #-----------------------
  # Compute R = 2S

  R = Point.fromAffine( C,
    H('00000128 79442f24 50c119e7 119a5f73 8be1f1eb a9e9d7c6 cf41b325 d9ce6d64 3106e9d6 1124a91a 96bcf201 305a9dee 55fa7913 6dc70083 1e54c3ca 4ff2646b d3c36bc6'),
    H('00000198 64a8b885 5c2479cb efe375ae 553e2393 271ed36f adfc4494 fc0583f6 bd035988 96f39854 abeae5f9 a6515a02 1e2c0eef 139e71de 610143f5 3382f410 4dccb543')
  )
  R2 = S.twice()
  test.assert R2.equals(R), "2S = R" 
  test.waypoint("twice 2S")

  #-----------------------
  # Compute R = dS

  d = H('000001eb 7f81785c 9629f136 a7e8f8c6 74957109 73555411 1a2a866f a5a16669 9419bfa9 936c78b6 2653964d f0d6da94 0a695c72 94d41b2d 6600de6d fcf0edcf c89fdcb1')
  R = Point.fromAffine( C,
    H('00000091 b15d09d0 ca0353f8 f96b93cd b13497b0 a4bb582a e9ebefa3 5eee61bf 7b7d041b 8ec34c6c 00c0c067 1c4ae063 318fb75b e87af4fe 859608c9 5f0ab477 4f8c95bb'),
    H('00000130 f8f8b5e1 abb4dd94 f6baaf65 4a2d5810 411e77b7 423965e0 c7fd79ec 1ae563c2 07bd255e e9828eb7 a03fed56 5240d2cc 80ddd2ce cbb2eb50 f0951f75 ad87977f')
  )
  R2 = S.multiply(d)
  test.assert R2.equals(R), "dS = R"
  test.waypoint("multiply dS")


  #-----------------------
  # Compute R = dS + eT

  e = H('00000137 e6b73d38 f153c3a7 57561581 2608f2ba b3229c92 e21c0d1c 83cfad92 61dbb17b b77a6368 2000031b 9122c2f0 cdab2af7 2314be95 254de429 1a8f85f7 c70412e3')
  R = Point.fromAffine( C,
    H('0000009d 3802642b 3bea152b eb9e05fb a247790f 7fc16807 2d363340 133402f2 585588dc 1385d40e bcb8552f 8db02b23 d687cae4 6185b275 28adb1bf 9729716e 4eba653d'),
    H('0000000f e44344e7 9da6f49d 87c10637 44e5957d 9ac0a505 bafa8281 c9ce9ff2 5ad53f8d a084a2de b0923e46 501de579 7850c61b 229023dd 9cf7fc7f 04cd35eb b026d89d')
  )
  R2 = S.multiplyTwo(d, T, e)
  test.assert R2.equals(R), "dS + eT = R"
  test.waypoint("multiply/add dS + eT")

  cb()

#===============================================================================================

