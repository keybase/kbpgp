
basex = require '../../lib/basex'

strings = [
  'NQ==',
  'JFw=',
  'tcsx',
  'Tu4GxA==',
  'auSjOaA=',
  'ZkefLR8+',
  'DFXXotba8Q==',
  'd5qIhsw1VDM=',
  'q3Ec9ylXeDkH',
  'aeMRo800op92Vg==',
  '6CLydI2A/4B+r8M=',
  'WgpKRQPUqRoQicJR',
  'fzmjwo6FoabVJhPdIA==',
  'nZz6BzabiiEIq1GRxVk=',
  'ZteBZ2Qbp34Kq2fRc/Nb',
  'yg0SmD5XTvXK1VjwMqVVJg==',
  'emEGr8uQk6GpNE6PZ4icS40=',
  'ZZt9wPUFV4n7C21G9hrdQvGA',
  'k1MjGIIYD2ABkR30OBXU+8a20g==',
  'IJPu5Z5ghkMhgN7MXWeBOIWRyB8=',
  'ff9tTmyoPOB9pOiB1Cg12SVU94M7',
  'QD/EC8c3xFm7/VMJLYtaB5azo4TqyA==',
  'H4yVVCDdCy+f8eTo9kG9x5rh9WASq7U=',
  'Bq8NaqWJ9GGd00AhG0ugpNx/KnDAPtgL',
  'MHw66BtRt6flLlYniGeR4XXln9CYw6tTVg==',
  'MQyfbTLVM2ESLGosXUeMh8yYCCW+JuYX/Rg=',
  'LN4ZhdTahBErHhBDJvFUjzTrO3XK7kMwART1',
  '7ZnFsclcvtxvCM/g16YhTUwmHGLMLWA1nzPBcg==',
  'd1+b8n41AzxvYEPxLAERCb9AO11ZAPlhwtngGak=',
  '01BRvAZDRxA4lqxkcwbTjRdFhQPh0GIELO1UK10g',
  '71Visyg38QyCAlF8Ew7S83TI9HSBjsXOFIahpQfPgg==',
  'wq/l5xnFHVztmuPeKZQ0J8fprk9mgTk+1VUrUujTpVg=',
  'mz8qyqnHR1pNxl/GAMqrRS8CwXlnRrxkBqlxOp1lTlCO',
  'rzkkddy7UQENsCK5U0ElOlbF2qLstOLiRuraGLpz9SNUXA==',
  '1ltKyVhAPk1IWqbUDLtiJr0RKFN7KIehtRw90te4uOHP4IU=',
  'NZpcohqwL235VaRe9Vftg6xyLAL0GGj8RvifQivJA40I+Zb6',
  'KQnpqdm+w4SKj64FfQlekz3WVI5rOIAaXo+fTXI8iBtiI8tzaQ==',
  'XSQlxRa/5jai5Mk7IZ8QkFBhQVsNiDzeq1fe0MP6g96JRoGNDrc=',
  '6FIMrVr3xoOljShd6MfBubn5eVDer55PdmKS05jYgyGVJVo2U9JK',
  'uPXwAqxHiSFV0SFTkqPL6nbsyPKiKzuSTBjA9mhsaUlUEXLFkSJXjQ==',
  'q+AQXCAkdA+QsVcZhRwMhUNL0uCx46ba1KQqEmFxen1p2y0vxPKPRUM=',
  'KNkPd6zKyHUzTbygaxgHsC4OhVUriW5PsZHYOskfR698FYorrfpKPc2u',
  'gJdEaGm/AQLJhbA7u0g6M8g/OHXEnRuqu5GJrS0y4WdWP94+blEZKTNrkw==',
  'LiTHO8mza95k8wxaSqx1UO4jAa9dMVUXRajJVmSEhml4I2AKlxhWYu8EroE=',
  'MZQ1bDAD8Aou4m39spZ2BGwqlLilDZa7JG/Y2DjhYsu1VGVcO54dcCdvh1Fw',
  'T5vgMk5i8geYWSXP7J0uhKJopVes2VdyD8RvkDLUYCtTLfFAsm6fyDHuKt5R5w==',
  'irP6uYjIN+2Jfd39TWED1hvOuWENLbIQpHF8oVz1LHNKN7M6i8VnQCnmhlVJp1o=',
  'h60iqpRrCy+NSL1FPVeHVm5VZczqq/Y8xJhmywisRdes8QbkObzxxNQxKBbj9SUq',
  'yGsQEKEO8SQz3FA9QNwAsRwFX7yuSkvcekrL92aSAx3mIlglY+tP/glRyVKd9BjQ+w==',
  'KmcUj6cC4DSw+L0QxdDlnoVybN5FVYcd55VeQAxpo5p6drxCylWoqL/yhHcDHuy22qs=',
  'DyczCfJ1dnxo7hFVbnA7bgB635Ctn2naLBS9zr5uSbnhAvPIhZKgMDV3IjeKgdFb0Qib',
  'lCoRzitr1J6ob6/14w/4oiwXNwerdUg3chalaxF7hq6KEs0aD0PWtJngBHQZTfb+kZk0ZQ==',
  '8SgKBZM482v20t4K49RLfrqCxgyc/pBBOJHbhFEmSwAJGQmXTzx9fchmerjGw9JWxE7Ebrk=',
  'HZUG8+W1frwYBfhtS3hkrEq+eT7nJRYvSZ7KurLIzBAwLod2nELHR4+EsbI1+2AS1VSXEaGd',
  'Llr0niQMO10f4ObG7rptspjbzsJLkwlhjCZJ4iPNKEEJy/WGyfaMl1vwKssBlHTdDIhdz6eNvA==',
  '7lofRAwvCYbVvINaN4DXvyAxVl4NaFE23dD9yRClaeMtv5aiiDn5/PAF1srsMIrF4yB5U1rO6Dw=',
  'JGFqnJcxggs58dohZrxo1Qbc7X8a/57COndxyZNG58CBkpFrmEb+OhvLd2U1nRRQVMeqswndePMj',
  'q/PVOgZ3yq7L9EqINLXjGtBjIz9c0Y/cvrBXbIVPav/YbutYxjyiPg6p3umEzolq5i271/UYq7NQfA==',
  '+wv8wAF8q7zQRggPwLwUgSQ/41+WklAsbQYaD/YE31AU+4l3GazcYEfjYqK4VeUsGvFT8BMjhFPVL00=',
  'S6iWWBd6QINRqtevBqoIdiykUFtdeI4LFT5HbkDb6qQ2olMt6dwfXNZKVpRWvvlt52RBn/8CBzCQ6EYW',
  'rOHrr7YbbXRC9bAm/hnOIf3mZ06HPx273kMuIHbNQDHkFVrU540Wx29ZmuCYtH/N/dU3kIsM5Qe41yF0Vg==',
  'nzYlka9T3MPeraGhm9Hbky1i+AOb9d1eCbnYXOmeNcPJXG10rFc+O7qTLbE0vx3a5CgHTIJ/EO1pB3zEvw4=',
  'NqSjv4rSJmcsYoN8RVSy9ZO/l6UeDhFllksB3L/1iTQ5Uuwv+v1W9/FPMZO3HZPHU5QEqM/ARRnFNFDWWB6t',
  'v24FgPNMu/2Lthf5B27N9jWfBjhBgvYmBl6hTGZWD3PfH1eV0vr3yqZc3h2YxByCT+aE+O5JGQKSbLbcjWR1mA==',
  '/rxfJVWHad84FJssrGDcM572nMumnlXgDCQoLmtttgtDbWD7/ZYI4dJgdKr8DkJTRBd7pRgUiUlp04r54+Z8h38=',
  'V3RG4TIc4bnqlvD/EC2O4JD/wkKxeyL+Ql9S96Ca27Tt9SmXtQYul3gjLtwPPCdNaHaSNNI8EZTV4CyflHUpK0kg',
  'SfaXsjVviQ8TDMebp6H+K2sCxPnpuCVefm6igmwVCiz4d8YYjuMNnR54G5VVg8kuEqGbwxxNHFx5n6od+Pw/Y0d1Ag==',
  'rylomwV5He3xdmL3XklUvoORFXbLK00xvZW71fAroA6fmbsGVXPZh88YH6217ZJ7UW8XpG0HxDeCtnSdTY4s1shJr8s=',
  'OnXcvJ/vMoj7JTYb3OkohJDAtmQTDqr2mcde+tvr/lnMj8ZQrx6TxyfcvQdQ9CmbPSPmixQ035cGi90kTBAo4t7+NQTK',
  '5rh22p73knoizl4vZHZ6WJe09AbTrVJZ5oUExxLHWvhxnHjASsXLpEyVo+0znp175FhWIDDJcscBo663NMxR6EvOiQapig==',
  'RVdl2RgTHGg69DwJ/Jx2PR+QB9kxUGKVWNXk+9ywohKn//NcMvywCrZKScMxZ1NzRX/sAQdx8AgEiUR+LDL5o3qK1NRdQL8=',
  'CUA6rcWYpzMg5/UGBHpyzJ/7nn5ea2RE6b9y+bwIOTJcEtLQ+F6Kpq4vfwUVMD5aW9Thz5VqFgrRT6kIjha7S4ygLS0tDKdK',
  '0UYI/SSDbzT0bZuNIcvWJgmmByZcsm8wVJSGW5eu/En1P5foiZdLndtNuOYSLEMgqleiSC+mBeh4WfYmPADAXheDf+IQDEfalQ==',
  'xD2CVGXZNb7Issh/hZ8XNA6qPq3LiTnL2veWHRknZEK9O3NF6y3W4sCabllylwcOYMMqv8h4bsG9Ewi5d3jMRRK+ol6dmttsd7M=',
  'VqlxR6L7KoacnslJ6Mje+ul2muVljAjlmoRDducYAVBqS46NlCqdCLFb//Jtryic0UnAV79AMRkppLBErQkcLsfOf/nK18Rtle2G',
  'aX/3p0Cl/lOtD2MKSqqRtgvFQdzCakhsetjUlJp+beehmZpfvC9rbmY05bmIGuh4CChfmY7O3wLveBfWn8HzaVlb2GE14fFjzfnKGA==',
  'dqIvI93OEXNHHpekn1R7Dn/lxZ9/L37iqu2Y9CmekKQFbKxd9KvbNTWuiJCUZnUcIZ/Ezs/kyFsN7roy3RnGPY2+q8gMNeDgu4QYkP4=',
  'eW2btCqOPabayGOrLZy7fH6OoTcXQCzNjmu1HTawMlnHBFvoLuxkuQE2XcBe5Buv1ZdltYpqSn7u6Vp7dPhpb1yTJrfUuVdsPBvbplFK',
  'v+IH2XmNy5AJn/EjBCqWPMZ51n8m6EKFmgFHRFCkWvDhwPdtFnVd+nae0pt4L5atcywuT3M0+GsB9n/WrhggHdRiXkcYJo1U6xl2+PYvKQ==',
  'mcqytgoiNpR4+r++8sBvOOx+Qnb43K5mlmXUxR8HItWE3k5jx4hwsZg656fCk3r66YASmMD/4MN05r3z2+rlhx34zeXsGlrbxilKj8iRYvg=',
  '9DitRHJsCKEV2yvZJpHJ5PfNgXKMVc/cQik+eTI5PYc8QglfGGB30BneLCCp3jrKFZ+VpvwrmR3Gocag7ljYGhF1hfN24jvvreJKkfrcSsJm',
  'DvA4RIvW0qSVvUCFqgH1ip06CyIRm+L9EthVUTz1syU1nGsE4YVk7A2FCbrbHrJtpDm/8MLwlaL2ygJ8X+QUjvo6tDpBQRUSbhTaZY54IARIoA==',
  'k1T6S92TKbXb9D+XzBcCTStOi+ZrJmZq1HCkXpY0Gy/A0z/D8aWCdkNtgFAeu9VU0iVcM0a8NuMeO9b7qE8jz33ggOiG2zoYuqQ1Lv0IaPEg2sI=',
  '4So9Z2fd3lFD1kAyvTGBsyeir5mMLbqvj0zCqZhgseoVebNkOO09f+Bes4n/YKiuToKfUKjsmzca2lzu9oTO9R03hBBJZrmyp7oP/Grl7oFkXwyK',
  'K2UjzOmkmZkZ2A67Zsh9nVhN3O9tPDox2RdZDO/Egf1SOdEqgW+VZ2K9W9ACjS++fMXF1YqNxMVyTP7LI5nU01CzYS6chFjcBui6bP47cSlUxPp0Xg==',
  'cuDzYJntu2b4LXg0kBr6xqeP7qFS46ZttiYAHb4wrWyDF7d2sWsoFlEXSwrj1jxqTwb8hNmEOdiSnWb8E4xkfFtDlOMKqyxNk2ll/Tmkk+V0q67OChY=',
  'sZDvFtY+L9e/CaVm9AYs+zdatWDn+SCpbtqdyMFnrhwsAwvWewElap6VPbsMU6G+Oh30qyVRUYIfmzL3MSERUE9EyekXBAWHR+iT1ipWfAXYI0qx0wOG',
  'WzzH3HGB4ndFTKEpsTxNdffzh5TKYtQGOhaIqG++TDCwDbTjpQ9LNayFE57OAUJV1qT7z1o5ESN2CzvpYMqID5mpNQ/1uuNhwZ6rzaZJ9YJdVvcP+zyMLw==',
  'K4RSVf/2pAhFpeWCVEeKO3j/llSj9YXoFnwZPorWCoFrWRWFvWx0NrwoIBZclacJ9PlO1/6B8CbmB3C9RHq6F+9c3CNdRg+K6d5XovKJbGrFh8YUGav+Nmk=',
  'AONTWMpp8q6lVyszsNRk+BhM0vtyml26OvWIQAdRfNxoJtnLZlRI0K/HhdARrbLE5MnmdkwaSdvAguNghD03FXkqhm4ioYMloSgeJ30wkg+U/ZezF9oZEvvL',
  'HMCeqmJFacHdCHJGIRMTjMDVuvte7dD5GJ8ud+ywmqVjvcu/euyTb2oilQJO0gruDrPK2iXfJ+GowiCIDuBkSnAHQO2R9l3TBIM45/qF/+XBBEZ5muQzlxPeww==',
  'ZMvhqVt7SvpdEQa1eUjfFBuOdWp2uTTZVyLkGnuGBhupq1rV5WXtCqg9jbDY/3f4mLdFapDodAy1qAIxNn/RljQHQst7KdU3v9RrVFSTvTNbP+v/6sUZxgv4IsY=',
  'im9s8F6G9LF1BzMvYmd9sWcQnL97b7rqUVEs5p6yCXfLwGGP1oCSe+WTrzXbK/jqf3snMd4nb0F1tqdeHlwQozbPdrf46M09m3/q3XFGAiyeEC5/B9RWuSPa5jFi',
  'DNJ1o9F/OBXDKWnuo2yMJsIJYMVkm8wg3aVWwGGTyhRkIrB6g3Z3oyMclJBw2EIhdDa0bCVWA3b7xAA3G1fnz5FpmhUSr42BnJoRVLsDzcB6oIH0hYXQC4jIsgvjKQ==',
  '4dJuWF8TBOT8pESi9sn+GJa1klNW5hJfLjfMOWRv2fNABIrt/xwyyGXpjIMnpa203pDXKLz79OAdMfr5lJ7UMQuz6349arCe9oY8nS5WRdjo8pdnH3taabB74QKfrvk=',
  'oQzpc901rsAh4YFWOiIYTf2tELEVdJwxLTfaOsJ9viNOCNlUj/al+V4Mn8dp9NTFwhw5KxTWzs24u2Bv3oHd2gtaN5WJGCI/IXtm8X8kmCHkQJ/jeeFsIQvPbCbXDUhv',
  'g3ng5pjxOXz2PV0NSFBg7rqW607RPi8Ey87hoNoWA6Oicbades3LIWzMRP2y5y/42szyXTxYSagCDzqvujiwtaGzO0EdQ8oxivrLs0is/p98f96I72gNhqGZAh4ZRVCc8g==',
  'XLv47EIDz+aWtymeoK2CxE2VxZYoPNSARobu147TE6OTUmnl2g2+QmNfVjfeoamSp5R9NphzJIlfxUtfAQcrwUmtZQ+0s7obxBAub5UGNSd51GiBaWs3H7n9bM72twaRnFA=',
  'g7MLX1WJzt8DZhvPcKkvnocrQyFop9YPJpyglXGN4Z3+62SV4lI0pNYxCIIMcROZrA6DE+TaikKHmoC/kZEI5XH++3gCKPhigEcV+A/f+yqOQxpPcSNNuqvb1TyIDSEXSgMC' ]


test_base = (T, klass, what) ->
  for padlen in [0...29] by 7
    pad = new Buffer (0 for i in [0...padlen])
    for s,i in strings 
      buf = Buffer.concat [ pad, new Buffer s, 'base64' ]
      s = buf.toString 'base64'
      e = klass.encode buf
      d = klass.decode e
      s2 = d.toString 'base64'
      T.equal s, s2, "#{what} string #{i}"

exports.test_base58 = (T, cb) ->
  test_base T, basex.base58, 'base58'
  cb()

exports.test_base32 = (T, cb) ->
  test_base T, basex.base32, 'base32'
  cb()
