import 'package:encrypt/encrypt.dart';
import 'package:fast_gbk/fast_gbk.dart';
import 'package:flutter/cupertino.dart';
import 'package:pointycastle/asymmetric/api.dart';

class RsaSign {
  static const keyPrefix = '-----BEGIN PRIVATE KEY-----';
  static const keySuffix = '-----END PRIVATE KEY-----';
  static String sign({@required String privateKey, @required String plainText, charset: SignCharset.GBK}) {
    String key = '''$keyPrefix
$privateKey
$keySuffix''';
    final keyParser = RSAKeyParser();
    final rsaPrivateKey = keyParser.parse(key) as RSAPrivateKey;
    final signer = Signer(RSASigner(RSASignDigest.SHA256, publicKey: null, privateKey: rsaPrivateKey));
    if(charset == SignCharset.GBK) {
      return signer.signBytes(gbk.encode(plainText)).base64;
    } else {
      return signer.sign(plainText).base64;
    }
  }
}

enum SignCharset {
  GBK,
  UTF8,
}