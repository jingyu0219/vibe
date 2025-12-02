import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.SecureRandom;

/**
 * Console tool that mimics Mattermost's bcrypt password hashing (v10.11.x) using Java 7.
 *
 * Usage examples:
 *   java -cp out MattermostPasswordHasher "password"
 *   java -cp out MattermostPasswordHasher --cost 12 "password"
 *   java -cp out MattermostPasswordHasher                # reads from stdin
 */
public class MattermostPasswordHasher {
    private static final int DEFAULT_COST = 10; // Mattermost default

    public static void main(String[] args) throws IOException {
        Arguments parsed = Arguments.parse(args);
        String password = parsed.password != null ? parsed.password : readPasswordFromStdIn();
        int cost = parsed.cost != null ? parsed.cost : DEFAULT_COST;

        String salt = BCrypt.gensalt(cost, new SecureRandom());
        String hashed = BCrypt.hashpw(password, salt);

        System.out.println(hashed);
    }

    private static String readPasswordFromStdIn() throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
        String line = reader.readLine();
        if (line == null) {
            throw new IOException("No input provided");
        }
        return line;
    }

    private static class Arguments {
        final Integer cost;
        final String password;

        private Arguments(Integer cost, String password) {
            this.cost = cost;
            this.password = password;
        }

        static Arguments parse(String[] args) {
            Integer cost = null;
            String password = null;

            for (int i = 0; i < args.length; i++) {
                if ("--cost".equals(args[i]) && i + 1 < args.length) {
                    cost = parseCost(args[++i]);
                } else {
                    password = args[i];
                }
            }

            return new Arguments(cost, password);
        }

        private static int parseCost(String value) {
            try {
                int parsed = Integer.parseInt(value);
                if (parsed < 4 || parsed > 31) {
                    throw new IllegalArgumentException("Cost must be between 4 and 31");
                }
                return parsed;
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("Invalid cost value: " + value, ex);
            }
        }
    }
}
