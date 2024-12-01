package comp3911.cwk2;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PasswordHashingUtility {

    private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";

    public static void main(String[] args) {
        try (Connection database = DriverManager.getConnection(CONNECTION_URL)) {
            updatePasswordsToHashed(database);
            System.out.println("Passwords have been successfully hashed.");
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }

public static void updatePasswordsToHashed(Connection database) {
    try {
        // Start a transaction
        database.setAutoCommit(false); 

        String query = "SELECT username, password FROM user";
        try (PreparedStatement pstmt = database.prepareStatement(query)) {
            ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                String username = rs.getString("username");
                String plainPassword = rs.getString("password");
                String hashedPassword = hashPassword(plainPassword);

                String updateQuery = "UPDATE user SET password = ? WHERE username = ?";
                try (PreparedStatement updateStmt = database.prepareStatement(updateQuery)) {
                    updateStmt.setString(1, hashedPassword);
                    updateStmt.setString(2, username);
                    updateStmt.executeUpdate();
                }
            }
        }

        database.commit(); 

    } catch (SQLException e) {
        System.err.println("Error updating passwords: " + e.getMessage());
        
        // try {
        //     database.rollback(); 
        //     System.out.println("Changes have been rolled back.");
        // } catch (SQLException rollbackEx) {
        //     System.err.println("Error during rollback: " + rollbackEx.getMessage());
        // }
    }
}


    private static String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hashedBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }
}
