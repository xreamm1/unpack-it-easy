import uie.fixture.Hello;
public class VerifyAndroid {
    public static void main(String[] args) {
        int[][] cases = {{0,0,0}, {2,3,5}, {-8,3,-5}, {-4,-2,-6},
                         {Integer.MAX_VALUE,1,Integer.MIN_VALUE}, {Integer.MIN_VALUE,-1,Integer.MAX_VALUE}};
        for (int[] row : cases) {
            if (Hello.add(row[0], row[1]) != row[2]) throw new AssertionError("sum");
        }
        if (!"uie owned fixture".equals(Hello.message())) throw new AssertionError("message");
        System.out.println("owned-android: 7 assertions passed");
    }
}
