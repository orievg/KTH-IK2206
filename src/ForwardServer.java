/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import java.lang.Integer;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.FileInputStream;
import java.util.Base64;

public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTHANDSHAKEPORT = 2206;
    public static final String DEFAULTHANDSHAKEHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;

    private ServerHandshake serverHandshake;
    private ServerSocket handshakeListenSocket;
    private static int targetPort;
    private static String targetHost;
    private static SessionEncrypter sessionEncrypter = null;
    private static SessionDecrypter sessionDecrypter = null;
    /**
     * Do handshake negotiation with client to authenticate and learn 
     * target host/port, etc.
     */
    private void doHandshake(Socket handshakeSocket) throws UnknownHostException, IOException, Exception {
        String userCertName = arguments.get("usercert");
        String caCertName = arguments.get("cacert");
        String handshakeport = arguments.get("handshakeport");

        //verify own certificate
        FileInputStream fUsr = new FileInputStream(userCertName);
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        X509Certificate certU = (X509Certificate) factory.generateCertificate(fUsr);
        fUsr.close();
        FileInputStream fCA = new FileInputStream(caCertName);
        X509Certificate certCA = (X509Certificate) factory.generateCertificate(fCA);
        fCA.close();
        byte[] encoded64_certUSR = Base64.getEncoder().encode(certU.getEncoded());
        String String64_certUSR = new String(encoded64_certUSR);
        serverHandshake = new ServerHandshake(handshakeSocket, String64_certUSR, certCA);
        targetHost = serverHandshake.targetHost;
        targetPort = serverHandshake.targetPort;
        this.sessionEncrypter = serverHandshake.sessionEncrypter;
        this.sessionDecrypter = serverHandshake.sessionDecrypter;
    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer() throws Exception {
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        ServerSocket handshakeListenSocket;
        try {
            handshakeListenSocket = new ServerSocket(port);
        } catch (IOException ioex) {
            throw new IOException("Unable to bind to port " + port + ": " + ioex);
        }

        log("Nakov Forward Server started on TCP port " + handshakeListenSocket.getLocalPort());
        // Accept client connections and process them until stopped
        while(true) {

            Socket handshakeSocket = handshakeListenSocket.accept();
            String clientHostPort = handshakeSocket.getInetAddress().getHostName() + ":" +
                handshakeSocket.getPort();
            Logger.log("Incoming handshake connection from " + clientHostPort);

            doHandshake(handshakeSocket);
            handshakeSocket.close();

            /*
             * Set up port forwarding between an established session socket to target host/port. 
             *
             */

            ForwardServerClientThread forwardThread;
            forwardThread = new ForwardServerClientThread(serverHandshake.sessionSocket,
                                                          targetHost, targetPort);
            if (sessionEncrypter != null && sessionDecrypter != null){
                forwardThread.encryptServerSession(sessionEncrypter,sessionDecrypter);
            } else System.out.println("The session is not encrypted!");
            forwardThread.start();
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args) throws Exception {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTHANDSHAKEPORT));
        arguments.setDefault("handshakehost", DEFAULTHANDSHAKEHOST);
        arguments.loadArguments(args);
        ForwardServer srv = new ForwardServer();
        srv.startForwardServer();
    }
 
}
