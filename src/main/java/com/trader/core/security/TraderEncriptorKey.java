package com.trader.core.security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class TraderEncriptorKey {
    private static String traderMainKey = null;
    private static String pwdKey = null;

    private static final String CIPHER_INSTANCE_WS = "AES/CBC/PKCS5Padding";
    private static final String CIPHER_INSTANCE_PASSWORD = "AES/ECB/PKCS5Padding";
    private static final String CIPHER_ALGORITHM = "AES";

    public static void initZeusEncriptorKey(String zeusMainKeyVal,
                                            String pwdKeyVal) {
        traderMainKey = zeusMainKeyVal;
        pwdKey = pwdKeyVal;
    }

    private static void validateZeusEncriptorKeys() throws Exception {
        if (traderMainKey == null ||
                traderMainKey.isEmpty() ||
            pwdKey == null ||
            pwdKey.isEmpty()) {
            throw new Exception("It's a must to initialize the keys");
        }
    }

    public static String encode(String txt) throws Exception {
        validateZeusEncriptorKeys();
        try {
            byte[] clientKeyBytes = traderMainKey.getBytes();
            SecretKeySpec clientKey = new SecretKeySpec(clientKeyBytes, 0, clientKeyBytes.length, CIPHER_ALGORITHM);
            Cipher encCipher = Cipher.getInstance(CIPHER_INSTANCE_WS);
            encCipher.init(Cipher.ENCRYPT_MODE, clientKey);
            byte[] ivBytes = encCipher.getIV();
            byte[] dataBytes = encCipher.doFinal(txt.getBytes(StandardCharsets.UTF_8));
            byte[] concat = new byte[ivBytes.length + dataBytes.length];
            System.arraycopy(ivBytes, 0, concat, 0, ivBytes.length);
            System.arraycopy(dataBytes, 0, concat, ivBytes.length, dataBytes.length);

            return DatatypeConverter.printBase64Binary(concat);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decode(String txt) throws Exception {
        return getDecodedString(txt, traderMainKey);
    }

    public static String encodePwd(String pwd) throws Exception {
        validateZeusEncriptorKeys();
        try {
            byte[] clientKeyBytes = pwdKey.getBytes();
            SecretKeySpec clientKey = new SecretKeySpec(clientKeyBytes, 0, clientKeyBytes.length, CIPHER_ALGORITHM);
            Cipher pwdCipher = Cipher.getInstance(CIPHER_INSTANCE_PASSWORD);
            pwdCipher.init(Cipher.ENCRYPT_MODE, clientKey);
            byte[] dataBytes = pwdCipher.doFinal(pwd.getBytes(StandardCharsets.UTF_8));

            return DatatypeConverter.printBase64Binary(dataBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decodePwd(String pwd) throws Exception {
        validateZeusEncriptorKeys();
        byte[] dataBytes = DatatypeConverter.parseBase64Binary(pwd);
        byte[] clientKeyBytes = pwdKey.getBytes();

        try {
            SecretKeySpec clientKey = new SecretKeySpec(clientKeyBytes, 0, clientKeyBytes.length, CIPHER_ALGORITHM);
            Cipher pwdCipher = Cipher.getInstance(CIPHER_INSTANCE_PASSWORD);
            pwdCipher.init(Cipher.DECRYPT_MODE, clientKey);

            return new String(pwdCipher.doFinal(dataBytes), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static String decodePrivateSettings(String setting) throws Exception {
        return setting;
    }

    private static String getDecodedString(String setting,
                                           String zeusMainSettingKey) throws Exception {
        validateZeusEncriptorKeys();
        byte[] dataBytes = DatatypeConverter.parseBase64Binary(setting);
        byte[] IV = Arrays.copyOfRange(dataBytes, 0, 16);
        byte[] data = Arrays.copyOfRange(dataBytes, 16, dataBytes.length);
        byte[] clientKeyBytes = zeusMainSettingKey.getBytes();

        try {
            SecretKeySpec clientKey = new SecretKeySpec(clientKeyBytes, 0, clientKeyBytes.length, CIPHER_ALGORITHM);
            Cipher decCipher = Cipher.getInstance(CIPHER_INSTANCE_WS);
            decCipher.init(Cipher.DECRYPT_MODE, clientKey, new IvParameterSpec(IV));

            return new String(decCipher.doFinal(data), StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        return null;
    }
}
