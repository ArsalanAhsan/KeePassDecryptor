import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2Estimator {

    public static void main(String[] args) {
        String databaseFile = "D:\\Philips University\\IT Security\\Project\\databases\\databases\\Ahsana.kdbx";
        String password = "4727";
        try {
            byte[] masterSeed = extractMasterSeed(databaseFile);
            int transformRounds = extractTransformRounds(databaseFile);

            int rounds = measurePBKDF2Speed(password, masterSeed);
            System.out.println("PBKDF2-HMAC-SHA256 rounds for ~1 second: " + rounds);

            int speed = 100;  // Example value, replace with actual measured speed

            // Key space sizes
            int numericKeySpace = (int) Math.pow(10, 4);
            int lowercaseKeySpace = numericKeySpace * 26;
            int lowercaseUppercaseKeySpace = numericKeySpace * 52;

            // Updating cracking time estimates
            double pbkdf2NumericTime = estimatePBKDF2Time(numericKeySpace, rounds, speed);
            double pbkdf2LowercaseTime = estimatePBKDF2Time(lowercaseKeySpace, rounds, speed);
            double pbkdf2LowercaseUppercaseTime = estimatePBKDF2Time(lowercaseUppercaseKeySpace, rounds, speed);

            System.out.println("Numeric key space PBKDF2 time: " + pbkdf2NumericTime + " seconds");
            System.out.println("Lowercase key space PBKDF2 time: " + pbkdf2LowercaseTime + " seconds");
            System.out.println("Lowercase & Uppercase key space PBKDF2 time: " + pbkdf2LowercaseUppercaseTime + " seconds");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] extractMasterSeed(String databaseFile) throws IOException {
        byte[] data = readFile(databaseFile);
        int masterSeedOffset = findHeaderOffset(data, (byte) 0x04);
        if (masterSeedOffset == -1) throw new IllegalArgumentException("Master seed not found");
        int masterSeedLength = ByteBuffer.wrap(data, masterSeedOffset + 1, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
        return Arrays.copyOfRange(data, masterSeedOffset + 3, masterSeedOffset + 3 + masterSeedLength);
    }

    public static int extractTransformRounds(String databaseFile) throws IOException {
        byte[] data = readFile(databaseFile);
        int transformRoundsOffset = findHeaderOffset(data, (byte) 0x06);
        if (transformRoundsOffset == -1) throw new IllegalArgumentException("Transform rounds not found");
        int transformRoundsLength = ByteBuffer.wrap(data, transformRoundsOffset + 1, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
        return ByteBuffer.wrap(data, transformRoundsOffset + 3, transformRoundsLength).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    public static int findHeaderOffset(byte[] data, byte headerId) {
        int offset = 12;  // Skip signature and version
        while (offset < data.length) {
            byte fieldId = data[offset];
            int length = ByteBuffer.wrap(data, offset + 1, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
            if (fieldId == headerId) {
                return offset;
            }
            offset += 3 + length;
        }
        return -1;
    }

    public static byte[] readFile(String filePath) throws IOException {
        File file = new File(filePath);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
    }

    public static byte[] pbkdf2DeriveKey(String password, byte[] salt, int rounds) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, rounds, 256);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    public static int measurePBKDF2Speed(String password, byte[] salt) throws Exception {
        int rounds = 1000;
        long startTime = System.currentTimeMillis();

        while (System.currentTimeMillis() - startTime < 1000) {
            pbkdf2DeriveKey(password, salt, rounds);
            rounds += 1000;
        }

        return rounds;
    }

    public static double estimatePBKDF2Time(int keySpace, int rounds, int speed) {
        return (double) keySpace / speed * (rounds / 10000.0);
    }
}
