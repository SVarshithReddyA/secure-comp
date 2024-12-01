// package comp3911.cwk2;

// import java.io.File;
// import java.io.FileWriter;
// import java.io.IOException;
// import java.io.PrintWriter;
// import java.sql.Connection;
// import java.sql.DriverManager;
// import java.sql.ResultSet;
// import java.sql.SQLException;
// import java.sql.Statement;
// import java.time.LocalDateTime;
// import java.time.format.DateTimeFormatter;
// import java.util.ArrayList;
// import java.util.HashMap;
// import java.util.List;
// import java.util.Map;

// import javax.servlet.ServletException;
// import javax.servlet.http.HttpServlet;
// import javax.servlet.http.HttpServletRequest;
// import javax.servlet.http.HttpServletResponse;

// import freemarker.template.Configuration;
// import freemarker.template.Template;
// import freemarker.template.TemplateException;
// import freemarker.template.TemplateExceptionHandler;

// @SuppressWarnings("serial")
// public class AppServlet extends HttpServlet {

//   private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
//   private static final String AUTH_QUERY = "select * from user where username='%s' and password='%s'";
//   private static final String SEARCH_QUERY = "select * from patient where surname='%s' collate nocase";
//   private static final String LOG_FILE_PATH = "inputs.log";

//   private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
//   private Connection database;

//   @Override
//   public void init() throws ServletException {
//     configureTemplateEngine();
//     connectToDatabase();
//   }

//   private void configureTemplateEngine() throws ServletException {
//     try {
//       fm.setDirectoryForTemplateLoading(new File("./templates"));
//       fm.setDefaultEncoding("UTF-8");
//       fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
//       fm.setLogTemplateExceptions(false);
//       fm.setWrapUncheckedExceptions(true);
//     }
//     catch (IOException error) {
//       throw new ServletException(error.getMessage());
//     }
//   }

//   private void connectToDatabase() throws ServletException {
//     try {
//       database = DriverManager.getConnection(CONNECTION_URL);
//     }
//     catch (SQLException error) {
//       throw new ServletException(error.getMessage());
//     }
//   }

//   // Log method to write inputs to a file
//   private void logInput(HttpServletRequest request, String username, String surname, boolean authSuccess) {
//     try (PrintWriter logWriter = new PrintWriter(new FileWriter(LOG_FILE_PATH, true))) {
//       LocalDateTime now = LocalDateTime.now();
//       DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
//       String timestamp = now.format(formatter);

//       String method = request.getMethod();
//       String requestUrl = request.getRequestURL().toString();
//       String authStatus = authSuccess ? "Authentication Success" : "Authentication Failed";
//       logWriter.println(String.format("%s - Method: %s, Request URL: %s, Username: %s, Surname: %s, %s", 
//                                       timestamp, 
//                                       method, 
//                                       requestUrl, 
//                                       username != null ? username : "N/A", 
//                                       surname != null ? surname : "N/A",
//                                       authStatus));
//     } catch (IOException e) {
//       // Log to system error stream if file logging fails
//       System.err.println("Failed to log input: " + e.getMessage());
//     }
//   }

//   @Override
//   protected void doGet(HttpServletRequest request, HttpServletResponse response)
//    throws ServletException, IOException {
//     try {
//       Template template = fm.getTemplate("login.html");
//       template.process(null, response.getWriter());
//       response.setContentType("text/html");
//       response.setStatus(HttpServletResponse.SC_OK);
//     }
//     catch (TemplateException error) {
//       response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
//     }
//   }

//   @Override
// protected void doPost(HttpServletRequest request, HttpServletResponse response)
//     throws ServletException, IOException {
//   // Get form parameters
//   String username = request.getParameter("username");
//   String password = request.getParameter("password");
//   String surname = request.getParameter("surname");

//   // Check authentication
//   boolean authSuccess = false;
//   try {
//     authSuccess = authenticated(username, password);
//   } catch (SQLException e) {
//     // Handle exception, log error and return a server error response
//     System.err.println("SQL Error: " + e.getMessage());
//     response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database error during authentication");
//     return;
//   }

//   // Log the input and authentication result
//   logInput(request, username, surname, authSuccess);

//   try {
//     if (authSuccess) {
//       // Get search results and merge with template
//       Map<String, Object> model = new HashMap<>();
//       model.put("records", searchResults(surname));
//       Template template = fm.getTemplate("details.html");
//       template.process(model, response.getWriter());
//     } else {
//       Template template = fm.getTemplate("invalid.html");
//       template.process(null, response.getWriter());
//     }
//     response.setContentType("text/html");
//     response.setStatus(HttpServletResponse.SC_OK);
//   } catch (Exception error) {
//     response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
//   }
// }

//   private boolean authenticated(String username, String password) throws SQLException {
//     String query = String.format(AUTH_QUERY, username, password);
//     try (Statement stmt = database.createStatement()) {
//       ResultSet results = stmt.executeQuery(query);
//       return results.next();
//     }
//   }

//   private List<Record> searchResults(String surname) throws SQLException {
//     List<Record> records = new ArrayList<>();
//     String query = String.format(SEARCH_QUERY, surname);
//     try (Statement stmt = database.createStatement()) {
//       ResultSet results = stmt.executeQuery(query);
//       while (results.next()) {
//         Record rec = new Record();
//         rec.setSurname(results.getString(2));
//         rec.setForename(results.getString(3));
//         rec.setAddress(results.getString(4));
//         rec.setDateOfBirth(results.getString(5));
//         rec.setDoctorId(results.getString(6));
//         rec.setDiagnosis(results.getString(7));
//         records.add(rec);
//       }
//     }
//     return records;
//   }
// }


// package comp3911.cwk2;

// import java.io.File;
// import java.io.FileWriter;
// import java.io.IOException;
// import java.io.PrintWriter;
// import java.sql.Connection;
// import java.sql.DriverManager;
// import java.sql.PreparedStatement;
// import java.sql.ResultSet;
// import java.sql.SQLException;
// import java.time.LocalDateTime;
// import java.time.format.DateTimeFormatter;
// import java.util.ArrayList;
// import java.util.HashMap;
// import java.util.List;
// import java.util.Map;

// import javax.servlet.ServletException;
// import javax.servlet.http.HttpServlet;
// import javax.servlet.http.HttpServletRequest;
// import javax.servlet.http.HttpServletResponse;

// import freemarker.template.Configuration;
// import freemarker.template.Template;
// import freemarker.template.TemplateException;
// import freemarker.template.TemplateExceptionHandler;

// @SuppressWarnings("serial")
// public class AppServlet extends HttpServlet {

//   private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
//   private static final String LOG_FILE_PATH = "inputs.log";

//   private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
//   private Connection database;

//   @Override
//   public void init() throws ServletException {
//     configureTemplateEngine();
//     connectToDatabase();
//   }

//   private void configureTemplateEngine() throws ServletException {
//     try {
//       fm.setDirectoryForTemplateLoading(new File("./templates"));
//       fm.setDefaultEncoding("UTF-8");
//       fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
//       fm.setLogTemplateExceptions(false);
//       fm.setWrapUncheckedExceptions(true);
//     } catch (IOException error) {
//       throw new ServletException(error.getMessage());
//     }
//   }

//   private void connectToDatabase() throws ServletException {
//     try {
//       database = DriverManager.getConnection(CONNECTION_URL);
//     } catch (SQLException error) {
//       throw new ServletException(error.getMessage());
//     }
//   }

//   private void logInput(HttpServletRequest request, String username, String surname, boolean authSuccess) {
//     try (PrintWriter logWriter = new PrintWriter(new FileWriter(LOG_FILE_PATH, true))) {
//       LocalDateTime now = LocalDateTime.now();
//       DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
//       String timestamp = now.format(formatter);

//       String method = request.getMethod();
//       String requestUrl = request.getRequestURL().toString();
//       String authStatus = authSuccess ? "Authentication Success" : "Authentication Failed";
//       logWriter.println(String.format("%s - Method: %s, Request URL: %s, Username: %s, Surname: %s, %s",
//                                       timestamp,
//                                       method,
//                                       requestUrl,
//                                       username != null ? username : "N/A",
//                                       surname != null ? surname : "N/A",
//                                       authStatus));
//     } catch (IOException e) {
//       System.err.println("Failed to log input: " + e.getMessage());
//     }
//   }

//   @Override
//   protected void doGet(HttpServletRequest request, HttpServletResponse response)
//    throws ServletException, IOException {
//     try {
//       Template template = fm.getTemplate("login.html");
//       template.process(null, response.getWriter());
//       response.setContentType("text/html");
//       response.setStatus(HttpServletResponse.SC_OK);
//     } catch (TemplateException error) {
//       response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
//     }
//   }

//   @Override
//   protected void doPost(HttpServletRequest request, HttpServletResponse response)
//       throws ServletException, IOException {
//     String username = request.getParameter("username");
//     String password = request.getParameter("password");
//     String surname = request.getParameter("surname");

//     boolean authSuccess = false;
//     try {
//       authSuccess = authenticated(username, password);
//     } catch (SQLException e) {
//       System.err.println("SQL Error: " + e.getMessage());
//       response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database error during authentication");
//       return;
//     }

//     logInput(request, username, surname, authSuccess);

//     try {
//       if (authSuccess) {
//         Map<String, Object> model = new HashMap<>();
//         model.put("records", searchResults(surname));
//         Template template = fm.getTemplate("details.html");
//         template.process(model, response.getWriter());
//       } else {
//         Template template = fm.getTemplate("invalid.html");
//         template.process(null, response.getWriter());
//       }
//       response.setContentType("text/html");
//       response.setStatus(HttpServletResponse.SC_OK);
//     } catch (Exception error) {
//       response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
//     }
//   }

//   private boolean authenticated(String username, String password) throws SQLException {
//     String query = "SELECT * FROM user WHERE username = ? AND password = ?";
//     try (PreparedStatement pstmt = database.prepareStatement(query)) {
//       pstmt.setString(1, username);
//       pstmt.setString(2, password);
//       try (ResultSet results = pstmt.executeQuery()) {
//         return results.next();
//       }
//     }
//   }

//   private List<Record> searchResults(String surname) throws SQLException {
//     List<Record> records = new ArrayList<>();
//     String query = "SELECT * FROM patient WHERE surname = ? COLLATE NOCASE";
//     try (PreparedStatement pstmt = database.prepareStatement(query)) {
//       pstmt.setString(1, surname);
//       try (ResultSet results = pstmt.executeQuery()) {
//         while (results.next()) {
//           Record rec = new Record();
//           rec.setSurname(results.getString(2));
//           rec.setForename(results.getString(3));
//           rec.setAddress(results.getString(4));
//           rec.setDateOfBirth(results.getString(5));
//           rec.setDoctorId(results.getString(6));
//           rec.setDiagnosis(results.getString(7));
//           records.add(rec);
//         }
//       }
//     }
//     return records;
//   }
// }




package comp3911.cwk2;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  private static final String LOG_FILE_PATH = "inputs.log";

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    } catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    } catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void logInput(HttpServletRequest request, String username, String surname, boolean authSuccess) {
    try (PrintWriter logWriter = new PrintWriter(new FileWriter(LOG_FILE_PATH, true))) {
      LocalDateTime now = LocalDateTime.now();
      DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
      String timestamp = now.format(formatter);

      String method = request.getMethod();
      String requestUrl = request.getRequestURL().toString();
      String authStatus = authSuccess ? "Authentication Success" : "Authentication Failed";
      logWriter.println(String.format("%s - Method: %s, Request URL: %s, Username: %s, Surname: %s, %s",
                                      timestamp,
                                      method,
                                      requestUrl,
                                      username != null ? username : "N/A",
                                      surname != null ? surname : "N/A",
                                      authStatus));
    } catch (IOException e) {
      System.err.println("Failed to log input: " + e.getMessage());
    }
  }

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
    try {
      Template template = fm.getTemplate("login.html");
      template.process(null, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname = request.getParameter("surname");

    boolean authSuccess = false;
    try {
      authSuccess = authenticated(username, password);
    } catch (SQLException e) {
      System.err.println("SQL Error: " + e.getMessage());
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database error during authentication");
      return;
    }

    logInput(request, username, surname, authSuccess);

    try {
      if (authSuccess) {
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      } else {
        Template template = fm.getTemplate("invalid.html");
        template.process(null, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

private boolean authenticated(String username, String password) throws SQLException {
    String query = "SELECT password FROM user WHERE username = ?";
    try (PreparedStatement pstmt = database.prepareStatement(query)) {
        pstmt.setString(1, username); 

        try (ResultSet results = pstmt.executeQuery()) {
            if (results.next()) {
                String storedHashedPassword = results.getString("password");

                String providedHashedPassword = hashPassword(password);
                return storedHashedPassword.equals(providedHashedPassword);
            }
        }
    }
    return false; 
}
private String hashPassword(String password) {
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


  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();
    String query = "SELECT * FROM patient WHERE surname = ? COLLATE NOCASE";
    try (PreparedStatement pstmt = database.prepareStatement(query)) {
      pstmt.setString(1, surname);
      try (ResultSet results = pstmt.executeQuery()) {
        while (results.next()) {
          Record rec = new Record();
          rec.setSurname(results.getString(2));
          rec.setForename(results.getString(3));
          rec.setAddress(results.getString(4));
          rec.setDateOfBirth(results.getString(5));
          rec.setDoctorId(results.getString(6));
          rec.setDiagnosis(results.getString(7));
          records.add(rec);
        }
      }
    }
    return records;
  }
}