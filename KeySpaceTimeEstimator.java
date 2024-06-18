public class KeySpaceTimeEstimator {

    public static void main(String[] args) {
        double speed = 12.183148447104484;  // Example value, replace with actual measured speed

        // Key space sizes
        int numericKeySpace = (int) Math.pow(10, 4);
        int lowercaseKeySpace = numericKeySpace * 26;
        int lowercaseUppercaseKeySpace = numericKeySpace * 52;

        // Rounds
        int rounds10000 = 10000;
        int rounds1000000 = 1000000;

        // Time calculations
        double numericTime10000 = estimateTime(numericKeySpace, rounds10000, speed);
        double numericTime1000000 = estimateTime(numericKeySpace, rounds1000000, speed);
        double lowercaseTime10000 = estimateTime(lowercaseKeySpace, rounds10000, speed);
        double lowercaseTime1000000 = estimateTime(lowercaseKeySpace, rounds1000000, speed);
        double lowercaseUppercaseTime10000 = estimateTime(lowercaseUppercaseKeySpace, rounds10000, speed);
        double lowercaseUppercaseTime1000000 = estimateTime(lowercaseUppercaseKeySpace, rounds1000000, speed);

        System.out.println("Numeric key space time (10000 rounds): " + numericTime10000 + " seconds");
        System.out.println("Numeric key space time (1000000 rounds): " + numericTime1000000 + " seconds");
        System.out.println("Lowercase key space time (10000 rounds): " + lowercaseTime10000 + " seconds");
        System.out.println("Lowercase key space time (1000000 rounds): " + lowercaseTime1000000 + " seconds");
        System.out.println("Lowercase & Uppercase key space time (10000 rounds): " + lowercaseUppercaseTime10000 + " seconds");
        System.out.println("Lowercase & Uppercase key space time (1000000 rounds): " + lowercaseUppercaseTime1000000 + " seconds");
    }

    private static double estimateTime(int keySpace, int rounds, double speed) {
        int baseRounds = 10000;
        return (keySpace / speed) * (rounds / (double) baseRounds);
    }
}
