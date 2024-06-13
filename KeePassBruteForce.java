import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import javax.crypto.Cipher;
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

    private static byte[] deriveKey(String password, byte[] database) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(password.getBytes());
        } catch (Exception e) {
            System.err.println("Error deriving key: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] decryptDatabase(byte[] key, byte[] database) {
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(database);
        } catch (Exception e) {
            System.err.println("Error decrypting database: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private static boolean isValid(byte[] decryptedData) {
        if (decryptedData == null) {
            return false;
        }

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
}
