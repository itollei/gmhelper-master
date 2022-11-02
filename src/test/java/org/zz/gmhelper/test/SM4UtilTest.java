package org.zz.gmhelper.test;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.SM4Util;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class SM4UtilTest extends GMBaseTest {
    private static String source = "123456abcdefg！@#￥%……&*（（";

    @Test
    public void testEncryptAndDecrypt() {
        try {
            byte[] key = "2IQCJfD0Kz1pZYpW".getBytes();
            byte[] iv = "0123456789876543".getBytes();
            byte[] cipherText = null;
            byte[] decryptedData = null;

//            cipherText = SM4Util.encrypt_Ecb_NoPadding(key, SRC_DATA_16B);
//            System.out.println("SM4 ECB NoPadding encrypt result:\n" + Arrays.toString(cipherText));
//            decryptedData = SM4Util.decrypt_Ecb_NoPadding(key, cipherText);
//            System.out.println("SM4 ECB NoPadding decrypt result:\n" + Arrays.toString(decryptedData));
//            if (!Arrays.equals(decryptedData, SRC_DATA_16B)) {
//                Assert.fail();
//            }
//
//            cipherText = SM4Util.encrypt_Ecb_Padding(key, SRC_DATA);
//            System.out.println("SM4 ECB Padding encrypt result:\n" + Arrays.toString(cipherText));
//            decryptedData = SM4Util.decrypt_Ecb_Padding(key, cipherText);
//            System.out.println("SM4 ECB Padding decrypt result:\n" + Arrays.toString(decryptedData));
//            if (!Arrays.equals(decryptedData, SRC_DATA)) {
//                Assert.fail();
//            }

//            cipherText = SM4Util.encrypt_Cbc_Padding(key, iv, source.getBytes());
//            System.out.println("SM4 CBC Padding encrypt result:\n" + ByteUtils.toHexString(cipherText).toUpperCase());
            cipherText = ByteUtils.fromHexString("7B11CE71E35E9C08F6DE845E2008EDCA6F3910877442691E28AD9E80088AC4E390D771E8356953E0E6580752EB7B622EC9456DE6556B483302BB2BF63656747C633B7CFE9ED9895E779ED025CEFC2E26425CD0D7E6E1C59F10C66B90DA1CDD52432CAE2874D0947628D350973AD37368");
            decryptedData = SM4Util.decrypt_Cbc_Padding(key, iv, cipherText);
            System.out.println("SM4 CBC Padding decrypt result:\n" + new String(decryptedData));
//            if (!Arrays.equals(decryptedData, SRC_DATA)) {
//                Assert.fail();
//            }

//            cipherText = SM4Util.encrypt_Cbc_NoPadding(key, iv, SRC_DATA_16B);
//            System.out.println("SM4 CBC NoPadding encrypt result:\n" + Arrays.toString(cipherText));
//            decryptedData = SM4Util.decrypt_Cbc_NoPadding(key, iv, cipherText);
//            System.out.println("SM4 CBC NoPadding decrypt result:\n" + Arrays.toString(decryptedData));
//            if (!Arrays.equals(decryptedData, SRC_DATA_16B)) {
//                Assert.fail();
//            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testMac() throws Exception {
        byte[] key = SM4Util.generateKey();
        byte[] iv = SM4Util.generateKey();

        byte[] mac = SM4Util.doCMac(key, SRC_DATA_24B);
        System.out.println("CMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());

        mac = SM4Util.doGMac(key, iv, 16, SRC_DATA_24B);
        System.out.println("GMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());

        byte[] cipher = SM4Util.encrypt_Cbc_NoPadding(key, iv, SRC_DATA_32B);
        byte[] cipherLast16 = Arrays.copyOfRange(cipher, cipher.length - 16, cipher.length);
        mac = SM4Util.doCBCMac(key, iv, null, SRC_DATA_32B);
        if (!Arrays.equals(cipherLast16, mac)) {
            Assert.fail();
        }
        System.out.println("CBCMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());

        cipher = SM4Util.encrypt_Cbc_Padding(key, iv, SRC_DATA_32B);
        cipherLast16 = Arrays.copyOfRange(cipher, cipher.length - 16, cipher.length);
        mac = SM4Util.doCBCMac(key, iv, SRC_DATA_32B);
        if (!Arrays.equals(cipherLast16, mac)) {
            Assert.fail();
        }
        System.out.println("CBCMAC:\n" + ByteUtils.toHexString(mac).toUpperCase());
    }
}
