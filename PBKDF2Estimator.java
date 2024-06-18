import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class PBKDF2Estimator {

    public static void main(String[] args) {
        String databaseFile = "D:\\Philips University\\IT Security\\Project\\databases\\databases\\Ahsana.kdbx";
        try {
            byte[] data = readFile(databaseFile);
            byte[] masterSeed = extractMasterSeed(data);
            int transformRounds = extractTransformRounds(data);

            System.out.println("Master Seed: " + Arrays.toString(masterSeed));
            System.out.println("Transform Rounds: " + transformRounds);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] readFile(String filePath) throws IOException {
        File file = new File(filePath);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        return data;
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
    public static byte[] extractMasterSeed(byte[] data) {
        int masterSeedOffset = findHeaderOffset(data, (byte) 0x04);
        if (masterSeedOffset == -1) throw new IllegalArgumentException("Master seed not found");
        int masterSeedLength = ByteBuffer.wrap(data, masterSeedOffset + 1, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
        return Arrays.copyOfRange(data, masterSeedOffset + 3, masterSeedOffset + 3 + masterSeedLength);
    }

    public static int extractTransformRounds(byte[] data) {
        int transformRoundsOffset = findHeaderOffset(data, (byte) 0x06);
        if (transformRoundsOffset == -1) throw new IllegalArgumentException("Transform rounds not found");
        int transformRoundsLength = ByteBuffer.wrap(data, transformRoundsOffset + 1, 2).order(ByteOrder.LITTLE_ENDIAN).getShort();
        return ByteBuffer.wrap(data, transformRoundsOffset + 3, transformRoundsLength).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }
}
