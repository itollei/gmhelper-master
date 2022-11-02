package org.zz.gmhelper.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.test.util.FileUtil;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;

public class SM2UtilTest extends GMBaseTest {

    private static String priK = "00FD4FADDB6CAC10D20EEF94093DA140B8AD95CEE983B115ADC28178705857E7CE";
    private static String pubX = "28AA86BE2F5ACA662033291E7DE78F5159B2B2D101B19C4026B8CD5526353E02";
    private static String pubY = "7FA0EBE7751B2DC55C99A1EB758B0CDC4BEE61DE9B9760E4FEE3F920DAFF0BFB";
    private static String source = "{\"responseCode\":\"000000\",\"responseContent\":\"操作成功!\",\"responseTime\":\"20221021152628\",\"agmTitle\":\"账号密码登录\",\"agmContent\":\"1、登录成功后，您可在我的-安全设置-指纹登录设置功能中，开启指纹登录功能，享受更便捷的指纹登录。\\n2、为了确保您的资金安全，任何情况下，请勿将你的登录密码、交易密码、云证通密码、短信验证码告知他人，以免造成您的资金损失。\"}Q0HlOiFKIwsMb29752pkGhWP4tzqWV2t000000操作成功!getAgreement\n";
//
//    public static void main(String[] args) {
//
//        SM2UtilTest.testEncryptAndDecrypt();
//    }

    @Test
    public void testSignAndVerify() {
        try {
//            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
//            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
//            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                    new BigInteger(ByteUtils.fromHexString(priK)), SM2Util.DOMAIN_PARAMS);
            ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(pubX, pubY, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);


            System.out.println("Pri Hex:"
                + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub Point Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            byte[] UID = "1234567812345678".getBytes("UTF-8");
            byte[] sign = SM2Util.sign(priKey, UID, source.getBytes());
//            byte[] sign = ByteUtils.fromHexString("304502205D2136DFD8F01CF4B59552C4826448694A52871DC6D08A943044B2F009500F7B022100995B09EAAC0DD7B6184B23ADC85493D3F45D7B22172E81667C345FF7B69A9487");
//            byte[] rawSign = SM2Util.decodeDERSM2Sign(sign);
            sign = SM2Util.encodeSM2SignToDER(sign);
            System.out.println("SM2 sign with UID result:\n" + ByteUtils.toHexString(sign).toUpperCase());
//            byte[] sign = Base64.decode("MEQCIAA5Xw90ONRVgeLLjoOt5rAWOIj//1EcqUAq6kDpxVyZAiBNFNm3DKqaTR0ai8ca9DR6Ex9dskrWhH+ydrNFQicVzQ==".getBytes(StandardCharsets.UTF_8));
            boolean flag = SM2Util.verify(pubKey, UID, source.getBytes(), sign);
            if (!flag) {
                Assert.fail("verify failed");
            }else {
                System.out.println("验证通过");
            }

//            sign = SM2Util.sign(priKey, SRC_DATA);
//            System.out.println("SM2 sign without UID result:\n" + ByteUtils.toHexString(sign));
//            flag = SM2Util.verify(pubKey, SRC_DATA, sign);
//            if (!flag) {
//                Assert.fail("verify failed");
//            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncryptAndDecrypt() {
        try {
//            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
//            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
//            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();


            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                    new BigInteger(ByteUtils.fromHexString(priK)), SM2Util.DOMAIN_PARAMS);
            ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(pubX, pubY, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

            System.out.println("Pri Hex:"
                + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub Point Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());


            source = "123456";
//            byte[] encryptedData = SM2Util.encrypt(pubKey, source.getBytes());
//            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(SM2Util.encodeSM2CipherToDER(encryptedData)).toUpperCase());

            byte[] encryptedData = ByteUtils.fromHexString("04F8B439A16C62BFB4DF90B62AEB33D36FE44D4D41900E5001EC3BEDABCF07B0D47A629A0AF9E40F341D066EE409BEA2440E00A48AEEA7E07FC2079065D4F9774F7063AFD794C012C0BF890406F47D3CE0B13F8CBA4F56FB842A4BB70029E36AD2139CB8EF674A".toUpperCase());
            byte[] decryptedData = SM2Util.decrypt(priKey, encryptedData);
//            byte[] decryptedData = SM2Util.decrypt(priKey, SM2Util.decodeDERSM2Cipher(encryptedData));
            System.out.println("SM2 decrypt result:\n" + new String(decryptedData));
            if (!Arrays.equals(decryptedData, source.getBytes())) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

//    @Test
    public void testKeyPairEncoding() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] priKeyPkcs8Der = BCECUtil.convertECPrivateKeyToPKCS8(priKey, pubKey);
//            System.out.println("private key pkcs8 der length:" + priKeyPkcs8Der.length);
//            System.out.println("private key pkcs8 der:" + ByteUtils.toHexString(priKeyPkcs8Der));
//            FileUtil.writeFile("D:/ec.pkcs8.pri.der", priKeyPkcs8Der);

            String priKeyPkcs8Pem = BCECUtil.convertECPrivateKeyPKCS8ToPEM(priKeyPkcs8Der);
            FileUtil.writeFile("D:/ec.pkcs8.pri.pem", priKeyPkcs8Pem.getBytes("UTF-8"));
            byte[] priKeyFromPem = BCECUtil.convertECPrivateKeyPEMToPKCS8(priKeyPkcs8Pem);
            if (!Arrays.equals(priKeyFromPem, priKeyPkcs8Der)) {
                throw new Exception("priKeyFromPem != priKeyPkcs8Der");
            }

            BCECPrivateKey newPriKey = BCECUtil.convertPKCS8ToECPrivateKey(priKeyPkcs8Der);

            byte[] priKeyPkcs1Der = BCECUtil.convertECPrivateKeyToSEC1(priKey, pubKey);
            System.out.println("private key pkcs1 der length:" + priKeyPkcs1Der.length);
            System.out.println("private key pkcs1 der:" + ByteUtils.toHexString(priKeyPkcs1Der));
            FileUtil.writeFile("D:/ec.pkcs1.pri", priKeyPkcs1Der);

            byte[] pubKeyX509Der = BCECUtil.convertECPublicKeyToX509(pubKey);
            System.out.println("public key der length:" + pubKeyX509Der.length);
            System.out.println("public key der:" + ByteUtils.toHexString(pubKeyX509Der));
            FileUtil.writeFile("D:/ec.x509.pub.der", pubKeyX509Der);

            String pubKeyX509Pem = BCECUtil.convertECPublicKeyX509ToPEM(pubKeyX509Der);
            FileUtil.writeFile("D:/ec.x509.pub.pem", pubKeyX509Pem.getBytes("UTF-8"));
            byte[] pubKeyFromPem = BCECUtil.convertECPublicKeyPEMToX509(pubKeyX509Pem);
            if (!Arrays.equals(pubKeyFromPem, pubKeyX509Der)) {
                throw new Exception("pubKeyFromPem != pubKeyX509Der");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

//    @Test
    public void testSM2KeyRecovery() {
        try {
            String priHex = "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D";
            String xHex = "FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913";
            String yHex = "F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String encodedPubHex = "04FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String signHex = "30450220213C6CD6EBD6A4D5C2D0AB38E29D441836D1457A8118D34864C247D727831962022100D9248480342AC8513CCDF0F89A2250DC8F6EB4F2471E144E9A812E0AF497F801";
            byte[] signBytes = ByteUtils.fromHexString(signHex);
            byte[] src = ByteUtils.fromHexString("0102030405060708010203040506070801020304050607080102030405060708");
            byte[] withId = ByteUtils.fromHexString("31323334353637383132333435363738");

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                new BigInteger(ByteUtils.fromHexString(priHex)), SM2Util.DOMAIN_PARAMS);
            ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

            if (!SM2Util.verify(pubKey, src, signBytes)) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

//    @Test
    public void testSM2KeyGen2() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub X Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

//    @Test
    public void testEncodeSM2CipherToDER() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA);

            byte[] derCipher = SM2Util.encodeSM2CipherToDER(encryptedData);
            FileUtil.writeFile("derCipher.dat", derCipher);

            byte[] decryptedData = SM2Util.decrypt(priKey, SM2Util.decodeDERSM2Cipher(derCipher));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

//    @Test
    public void testGenerateBCECKeyPair() {
        try {
            KeyPair keyPair = SM2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = BCECUtil.convertPrivateKeyToParameters((BCECPrivateKey) keyPair.getPrivate());
            ECPublicKeyParameters pubKey = BCECUtil.convertPublicKeyToParameters((BCECPublicKey) keyPair.getPublic());

            byte[] sign = SM2Util.sign(priKey, WITH_ID, SRC_DATA);
            boolean flag = SM2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            sign = SM2Util.sign(priKey, SRC_DATA);
            flag = SM2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }
}
