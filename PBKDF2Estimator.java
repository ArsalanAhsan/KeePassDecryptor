import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PBKDF2Estimator {

    public static void main(String[] args) {
        String databaseFile = "D:\\Philips University\\IT Security\\Project\\databases\\databases\\Ahsana.kdbx";
        try {
            byte[] data = readFile(databaseFile);
            int masterSeedOffset = findHeaderOffset(data, (byte) 0x04);
            int transformRoundsOffset = findHeaderOffset(data, (byte) 0x06);

            if (masterSeedOffset == -1 || transformRoundsOffset == -1) {
                throw new IllegalArgumentException("Master seed or transform rounds not found");
            }

            // Further processing will be added in subsequent commits

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
}
