import uie.quality.JavaFixture;
public class VerifyJava {
    static void equal(Object actual, Object expected) {
        if (!expected.equals(actual)) throw new AssertionError(actual + " != " + expected);
    }
    public static void main(String[] args) {
        int[] inputs = {-7, -1, 0, 1, 2, 5, 10};
        int[] expected = {7, 1, 0, -1, 1, -3, 5};
        for (int i = 0; i < inputs.length; i++) equal(JavaFixture.score(inputs[i]), expected[i]);
        equal(JavaFixture.label(" a ", 3), "a:a:a");
        equal(JavaFixture.label("", 2), ":");
        equal(JavaFixture.label("x", 0), "");
        equal(JavaFixture.label("x", -2), "");
        equal(JavaFixture.label("\u044f", 1), "\u044f");
        System.out.println("owned-java: 12 assertions passed");
    }
}
