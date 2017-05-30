package com.ckex.security;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 功能描述
 * <p></p >
 * <a href=" "><i>View Source</i></a >
 *
 * @author ckex868@vip.qq.com
 * @version 1.0
 * @date 30/05/2017
 * @since 1.0
 */
public class RsaUtils {

    private static final String ALGORITHM = "RSA";

    public static PrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(new Base64().decode(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    public static PublicKey getPublicKey(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(new Base64().decode(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }

    public static byte[] rsaDecode(Key key, String text) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(new Base64().decode(text));
    }

    public static String rsaEncode(Key key, String text) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new Base64().encodeAsString(cipher.doFinal(StringUtils.getBytesUtf8(text)));
    }

}
