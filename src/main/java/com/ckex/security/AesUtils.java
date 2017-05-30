package com.ckex.security;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

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
public class AesUtils {

    private static final String ALGORITHM = "AES";

    private static Key generateKey(String password) throws Exception {
        Key key = new SecretKeySpec(StringUtils.getBytesUtf8(password), ALGORITHM);
        return key;
    }

    public static String encode(String password, String content) throws Exception {
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.ENCRYPT_MODE, generateKey(password));
        byte[] encVal = c.doFinal(StringUtils.getBytesUtf8(content));
        return new Base64().encodeAsString(encVal);
    }

    public static String decode(String password, String content) throws Exception {
        Cipher c = Cipher.getInstance(ALGORITHM);
        c.init(Cipher.DECRYPT_MODE, generateKey(password));
        byte[] decValue = c.doFinal(new Base64().decode(content));
        return StringUtils.newStringUtf8(decValue);
    }

}
