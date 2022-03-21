public class Singpass_Crypto {
  static final Integer NONCE_LENGTH = 16;
  static final String NONCE_POSSIBLE_CHARS = '0123456789abcdef';

  public static String generateNonce() {    
    String nonce = '';
    
    while (nonce.length() < NONCE_LENGTH) {
        Integer i = Math.mod(Math.abs(Crypto.getRandomInteger()), NONCE_POSSIBLE_CHARS.length());
        nonce += NONCE_POSSIBLE_CHARS.substring(i, i + 1);
    }
    
    return EncodingUtil.convertToHex(Blob.valueOf(nonce));
  }
}
