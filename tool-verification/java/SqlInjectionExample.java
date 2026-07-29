import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class SqlInjectionExample {

    public static void main(String[] args) throws Exception {
        String userId = args[0];

        Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/testdb", "root", "");
        Statement stmt = conn.createStatement();

        // Vulnerable: user input concatenated directly into the query string.
        String query = "SELECT name FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            System.out.println(rs.getString("name"));
        }
    }
}
