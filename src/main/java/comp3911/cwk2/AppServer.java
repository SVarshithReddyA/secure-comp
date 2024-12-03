package comp3911.cwk2;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.util.log.StdErrLog;

public class AppServer {
  public static void main(String[] args) throws Exception {
    // Set the logging mechanism for Jetty to standard error logging
    Log.setLog(new StdErrLog());

    // Create a handler to manage servlets
    ServletHandler handler = new ServletHandler();
    handler.addServletWithMapping(AppServlet.class, "/*");

    // Create a new server instance listening on port 8080
    Server server = new Server(8080);
    server.setHandler(handler);

    server.start();
    server.join();
  }
}