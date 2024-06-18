import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeePassDecryptor {

    private static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    private static byte[] deriveKey(String password, byte[] masterSeed, byte[] transformSeed, int transformRounds) throws Exception {
        byte[] credentials = sha256(sha256(password.getBytes("UTF-8")));
        byte[] transformedCredentials = credentials;

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(transformSeed, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        for (int i = 0; i < transformRounds; i++) {
            transformedCredentials = cipher.doFinal(transformedCredentials);
        }

        byte[] keyMaterial = new byte[masterSeed.length + transformedCredentials.length];
        System.arraycopy(masterSeed, 0, keyMaterial, 0, masterSeed.length);
        System.arraycopy(transformedCredentials, 0, keyMaterial, masterSeed.length, transformedCredentials.length);

        return sha256(keyMaterial);
    }

    private static byte[] decryptDatabase(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] decryptedData = cipher.doFinal(data);
        int padLength = decryptedData[decryptedData.length - 1] & 0xFF;

        if (padLength > 0 && padLength <= 16) {
            return Arrays.copyOfRange(decryptedData, 0, decryptedData.length - padLength);
        }
        return null;
    }

    private static int[] findHeaderOffset(byte[] data, byte headerId) {
        int offset = 12; // Skip signature and version
        while (offset < data.length) {
            byte fieldId = data[offset];
            int length = ByteBuffer.wrap(data, offset + 1, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).getShort();
            if (fieldId == headerId) {
                return new int[]{offset + 3, length};
            }
            offset += 3 + length;
        }
        return new int[]{-1, 0};
    }

    private static int findEndOfHeader(byte[] data) {
        int offset = 12; // Skip signature and version
        while (offset < data.length) {
            byte fieldId = data[offset];
            int length = ByteBuffer.wrap(data, offset + 1, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).getShort();
            if (fieldId == 0x00) {
                return offset + 3;
            }
            offset += 3 + length;
        }
        return -1;
    }

    public static double measureDecryptionSpeed(String databaseFile, int durationInSeconds) throws Exception {
        long startTime = System.currentTimeMillis();
        long endTime = startTime + durationInSeconds * 1000;
        int attempts = 0;

        File file = new File(databaseFile);
        byte[] data = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(data);
        }

        int[] masterSeedInfo = findHeaderOffset(data, (byte) 0x04);
        int[] transformSeedInfo = findHeaderOffset(data, (byte) 0x05);
        int[] transformRoundsInfo = findHeaderOffset(data, (byte) 0x06);
        int[] ivInfo = findHeaderOffset(data, (byte) 0x07);
        int[] streamStartBytesInfo = findHeaderOffset(data, (byte) 0x09);

        byte[] masterSeed = Arrays.copyOfRange(data, masterSeedInfo[0], masterSeedInfo[0] + masterSeedInfo[1]);
        byte[] transformSeed = Arrays.copyOfRange(data, transformSeedInfo[0], transformSeedInfo[0] + transformSeedInfo[1]);
        int transformRounds = ByteBuffer.wrap(data, transformRoundsInfo[0], transformRoundsInfo[1]).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] iv = Arrays.copyOfRange(data, ivInfo[0], ivInfo[0] + ivInfo[1]);
        byte[] streamStartBytes = Arrays.copyOfRange(data, streamStartBytesInfo[0], streamStartBytesInfo[0] + streamStartBytesInfo[1]);

        int encryptedDataOffset = findEndOfHeader(data);
        byte[] encryptedData = Arrays.copyOfRange(data, encryptedDataOffset, data.length);

        if (encryptedData.length % 16 != 0) {
            encryptedData = Arrays.copyOf(encryptedData, encryptedData.length + (16 - encryptedData.length % 16));
        }

        System.out.println("Starting brute-force attempt for " + durationInSeconds + " seconds...");

        while (System.currentTimeMillis() < endTime) {
            for (int password = 0; password < 10000; password++) {
                String passwordStr = String.format("%04d", password);
                byte[] key = deriveKey(passwordStr, masterSeed, transformSeed, transformRounds);
                byte[] decryptedData = decryptDatabase(encryptedData, key, iv);
                attempts++;

                if (System.currentTimeMillis() >= endTime) {
                    break;
                }
            }
        }

        long elapsedTime = System.currentTimeMillis() - startTime;
        return (double) attempts / (elapsedTime / 1000.0);
    }

    public static void main(String[] args) {
        try {
            String databaseFile = "D:\\Philips University\\IT Security\\Project\\databases\\databases\\Ahsana.kdbx";
            double speed = measureDecryptionSpeed(databaseFile, 10);
            System.out.println("Passwords tested per second: " + speed);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
