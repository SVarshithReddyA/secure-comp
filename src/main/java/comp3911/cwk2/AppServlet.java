package comp3911.cwk2;

import java.io.File;
import java.io.FileInputStream;
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
import java.util.Properties;

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

  private String connectionUrl;
  private String logFilePath;
  private String queryUserPassword;
  private String queryPatientGpId;
  private String queryUserId;
  private String queryPatientDetails;

  // Instance of a rate limiter to handle login attempts
  private final RateLimiter rateLimiter = new RateLimiter();

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  // Intialization
  @Override
  public void init() throws ServletException {
    loadEnvVariables();
    configureTemplateEngine();
    connectToDatabase();
  }

  // Loads enviromental variables from .env file to configure the servlet
  private void loadEnvVariables() throws ServletException {
    Properties env = new Properties();
    try (FileInputStream fis = new FileInputStream(".env")) {
      env.load(fis);
      connectionUrl = env.getProperty("DB_CONNECTION_URL");
      logFilePath = env.getProperty("DB_LOG_FILE_PATH");
      queryUserPassword = env.getProperty("QUERY_USER_PASSWORD");
      queryPatientGpId = env.getProperty("QUERY_PATIENT_GP_ID");
      queryUserId = env.getProperty("QUERY_USER_ID");
      queryPatientDetails = env.getProperty("QUERY_PATIENT_DETAILS");
    } catch (IOException e) {
      throw new ServletException("Failed to load environment variables", e);
    }
  }

  // Configures freemarker template for rendering HTML templates
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

  // Establishes a connection to the database 
  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(connectionUrl);
    } catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }


  // HTTP request handlers 
  // Handles GET requests (from login page)
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
   throws ServletException, IOException {
    try {
      // Load the login template, and continues if there is not exception
      Template template = fm.getTemplate("login.html");
      template.process(null, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (TemplateException error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  // Handles POST requests for user authentication and patient data retrieval
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname = request.getParameter("surname");

    String authStatus;

    // Checks rate limiting for login attempts
    if (!rateLimiter.isAllowed(username)) {
      authStatus = "Rate Limited";
      logInput(request, username, surname, authStatus);
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Too many login attempts. Please try again later.");
      return;
    }

    // Authenticates the user
    boolean authSuccess = false;
    try {
      authSuccess = authenticated(username, password);
    } catch (SQLException e) {
      System.err.println("SQL Error: " + e.getMessage());
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database error during authentication");
      return;
    }

    // Validates GP ID matches user ID
    boolean isValidGp = false;
    try {
      isValidGp = isGpIdMatching(surname, username);
      if (!isValidGp) {
        logInput(request, username, surname, "Authentication Failed (Unauthorized user)");
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "You are not responsible for this patient");
        return;
      }
    } catch (SQLException e) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database error during authentication");
    }

    // Resets rate limiter for successful login
    if (authSuccess) {
      rateLimiter.reset(username);
    }
    authStatus = authSuccess ? "Authentication Success" : "Authentication Failed";
    logInput(request, username, surname, authStatus);

    try {
      if (authSuccess) {
        // Load patient details page only if the authentication is successful 
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      } else {
        // Load invalid page
        Template template = fm.getTemplate("invalid.html");
        template.process(null, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (Exception error) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
  }

  // Utility methods
  // Logs the details of HTTP requests and their authentication status 
  private void logInput(HttpServletRequest request, String username, String surname, String authStatus) {
    try (PrintWriter logWriter = new PrintWriter(new FileWriter(logFilePath, true))) {
      LocalDateTime now = LocalDateTime.now();
      DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
      String timestamp = now.format(formatter);

      String method = request.getMethod();
      String requestUrl = request.getRequestURL().toString();
      logWriter.println(String.format("%s - Method: %s, Request URL: %s, Username: %s, Surname: %s, Status: %s",
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

  // Method to authenticate a user by comparing provided password with stored hashed password
  private boolean authenticated(String username, String password) throws SQLException {
      // Prepare the SQL query to retrieve the stored hashed password for the given username
      try (PreparedStatement pstmt = database.prepareStatement(queryUserPassword)) {
          pstmt.setString(1, username); 
          try (ResultSet results = pstmt.executeQuery()) {
              if (results.next()) {
                  // Retrieve the stored hashed password from the database
                  String storedHashedPassword = results.getString("password");
                  String providedHashedPassword = hashPassword(password);
                  return storedHashedPassword.equals(providedHashedPassword);
              }
          }
      }
      return false;
  }

  // Validates that the user's ID matches the GP ID of the patient with the given surname
  private boolean isGpIdMatching(String surname, String username) throws SQLException {
    try (
        PreparedStatement patientStmt = database.prepareStatement(queryPatientGpId);
        PreparedStatement userStmt = database.prepareStatement(queryUserId)
    ) {
      patientStmt.setString(1, surname); 
      Integer gpId = null;
      try (ResultSet patientResult = patientStmt.executeQuery()) {
        if (patientResult.next()) {
          gpId = patientResult.getInt("gp_id");
        } else {
          return false;
        }
      }

      userStmt.setString(1, username);
      Integer userId = null;
      try (ResultSet userResult = userStmt.executeQuery()) {
        if (userResult.next()) {
          userId = userResult.getInt("id");
        } else {
          return false;
        }
      }

      return gpId != null && gpId.equals(userId);
    }
  }



  // Method to hash the provided password using SHA-256 algorithm
  private String hashPassword(String password) {
      try {
          // Create a MessageDigest instance for the SHA-256 algorithm
          MessageDigest digest = MessageDigest.getInstance("SHA-256");
          // Generate the hash by applying the digest function to the password bytes
          byte[] hashedBytes = digest.digest(password.getBytes());
          StringBuilder sb = new StringBuilder();
          for (byte b : hashedBytes) {
              // Append each byte formatted as two-digit hexadecimal
              sb.append(String.format("%02x", b));
          }
          return sb.toString();
      } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException("SHA-256 algorithm not found", e);
      }
  }



  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();
    String query = queryPatientDetails;
    // Prepare the SQL query using a prepared statement to prevent SQL injection
    try (PreparedStatement pstmt = database.prepareStatement(query)) {
      // Set the surname parameter in the prepared statement
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