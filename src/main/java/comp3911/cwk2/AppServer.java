package comp3911.cwk2;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;

public class AppServer {

    public static void main(String[] args) throws Exception {
        // Load environment variables from .env file
        Properties env = new Properties();
        String defaultPassword;
        try (FileInputStream fis = new FileInputStream(".env")) {
            env.load(fis);
            defaultPassword = env.getProperty("DEFAULT_PASSWORD");
            if (defaultPassword == null || defaultPassword.isEmpty()) {
                throw new IllegalArgumentException("DEFAULT_PASSWORD not found in .env file");
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load .env file", e);
        }

        // Create a Jetty server instance
        Server server = new Server();

        // Configure SSL
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setKeyStorePath("certs/server.p12");

        // Set the keystore type to PKCS12
        sslContextFactory.setKeyStoreType("PKCS12");

        sslContextFactory.setKeyStorePassword(defaultPassword);

        // Set up an SSL connector
        ServerConnector sslConnector = new ServerConnector(server, new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory());
        sslConnector.setPort(8080); // SSL port
        server.addConnector(sslConnector);

        // Set up the servlet handler
        ServletHandler handler = new ServletHandler();
        handler.addServletWithMapping(AppServlet.class, "/*");

        // Attach the handler to the server
        server.setHandler(handler);

        // Start the server
        server.start();
        server.join();
    }
}
