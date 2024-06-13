import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeePassBruteForce {

    public static void main(String[] args) {
        String filename = "D:\\Philips University\\IT Security\\Project\\databases\\databases\\Ahsana.kdbx";
        byte[] database = loadDatabase(filename);

        if (database == null) {
            System.err.println("Failed to load database. Exiting.");
            return;
        }

        for (int i = 0; i < 10000; i++) {  // 4-digit numbers
            String password = String.format("%04d", i);  // Pad with leading zeros
            byte[] key = deriveKey(password, database);

            if (key == null) {
                System.err.println("Failed to derive key for password: " + password);
                continue;
            }

            byte[] decrypted = decryptDatabase(key, database);

            if (decrypted != null && isValid(decrypted)) {
                System.out.println("Cracked! The password is " + password);
                break;
            }
        }
    }

    private static byte[] loadDatabase(String filename) {
        try {
            Path filePath = Paths.get(filename);
            if (!Files.exists(filePath)) {
                System.err.println("File does not exist: " + filename);
                return null;
            }
            if (!Files.isReadable(filePath)) {
                System.err.println("File is not readable: " + filename);
                return null;
            }
            return Files.readAllBytes(filePath);
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] parseHeaderField(byte[] database, byte id) {
        int offset = 12; // Start after the signature and version (8 bytes) and skip the first end of header field (4 bytes)

        while (offset < database.length) {
            byte currentId = database[offset];
            short length = byteArrayToShort(Arrays.copyOfRange(database, offset + 1, offset + 3));

            if (currentId == id) {
                return Arrays.copyOfRange(database, offset + 3, offset + 3 + length);
            }

            if (currentId == 0) { // ID 0: end of header
                break; // Stop parsing if we reach the end of header
            }

            offset += 3 + length; // Move to the next header field
        }

        return null; // Header field not found
    }

    private static int parseTransformRounds(byte[] database) {
        byte[] roundsData = parseHeaderField(database, (byte) 6); // ID 6: transform rounds
        if (roundsData != null && roundsData.length >= 4) {
            return byteArrayToInt(roundsData);
        }
        return 0;
    }

    private static byte[] deriveKey(String password, byte[] database) {
        try {
            byte[] masterSeed = parseHeaderField(database, (byte) 4); // ID 4: master seed
            byte[] transformSeed = parseHeaderField(database, (byte) 5); // ID 5: transform seed
            int transformRounds = parseTransformRounds(database); // ID 6: transform rounds

            if (masterSeed == null || transformSeed == null || transformRounds == 0) {
                throw new IllegalArgumentException("Master seed, transform seed, or transform rounds not found or invalid.");
            }

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            // First SHA-256 hashing of password
            byte[] credentials = sha256.digest(sha256.digest(password.getBytes()));

            // Applying transform rounds
            for (int i = 0; i < transformRounds; i++) {
                byte[] combined = new byte[transformSeed.length + credentials.length];
                System.arraycopy(transformSeed, 0, combined, 0, transformSeed.length);
                System.arraycopy(credentials, 0, combined, transformSeed.length, credentials.length);
                credentials = sha256.digest(combined);
            }

            // Deriving key
            byte[] combined = new byte[masterSeed.length + credentials.length];
            System.arraycopy(masterSeed, 0, combined, 0, masterSeed.length);
            System.arraycopy(credentials, 0, combined, masterSeed.length, credentials.length);

            // Truncate or expand the combined key material to fit the required length (e.g., 32 bytes for AES-256)
            return Arrays.copyOf(sha256.digest(combined), 32);
        } catch (Exception e) {
            System.err.println("Error deriving key: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] decryptDatabase(byte[] key, byte[] database) {
        try {
            byte[] iv = parseHeaderField(database, (byte) 7); // ID 7: encryption initialization vector (IV)

            // Skip header fields to the encrypted data
            int headerLength = calculateHeaderLength(database);
            byte[] encryptedData = Arrays.copyOfRange(database, headerLength, database.length);

            // Initialize AES cipher in CBC mode with PKCS5Padding
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            return cipher.doFinal(encryptedData);
        } catch (Exception e) {
            System.err.println("Error decrypting database: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private static int calculateHeaderLength(byte[] database) {
        int offset = 12; // Start after the signature and version (8 bytes) and skip the first end of header field (4 bytes)

        while (offset < database.length) {
            byte currentId = database[offset];
            short length = byteArrayToShort(Arrays.copyOfRange(database, offset + 1, offset + 3));

            if (currentId == 0) { // ID 0: end of header
                return offset + 3;
            }

            offset += 3 + length; // Move to the next header field
        }

        return database.length; // Default to end of file
    }

    private static boolean isValid(byte[] decryptedData) {
        byte[] expectedStreamStartBytes = new byte[] {
                (byte) 0x31, (byte) 0xC1, (byte) 0xF2, (byte) 0xE6,
                (byte) 0xBF, (byte) 0x71, (byte) 0x43, (byte) 0x50,
                (byte) 0xBE, (byte) 0x58, (byte) 0x05, (byte) 0x21,
                (byte) 0x6A, (byte) 0xFC, (byte) 0x5A, (byte) 0xFF
        };

        if (decryptedData.length >= 32) {
            for (int i = 0; i < 16; i++) {
                if (decryptedData[i] != expectedStreamStartBytes[i]) {
                    return false; // Stream start bytes do not match
                }
            }
            return true; // Valid database
        }

        return false; // Invalid database (too short)
    }

    private static short byteArrayToShort(byte[] bytes) {
        return (short) ((bytes[0] << 8) | (bytes[1] & 0xFF));
    }

    private static int byteArrayToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                (bytes[3] & 0xFF);
    }
}
