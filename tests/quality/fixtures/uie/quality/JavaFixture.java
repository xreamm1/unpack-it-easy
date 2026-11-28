package uie.quality;
public final class JavaFixture {
    public static int score(int n) {
        if (n < 0) return -n;
        int sum = 0;
        for (int i = 0; i <= n; i++) {
            if ((i & 1) == 0) sum += i;
            else sum -= i;
        }
        return sum;
    }
    public static String label(String text, int count) {
        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i < count) {
            if (i > 0) result.append(":");
            result.append(text.trim());
            i++;
        }
        return result.toString();
    }
}
