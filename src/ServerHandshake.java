/**
 * Server side of the handshake.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
    
    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;    

    /* The final destination -- simulate handshake with constants */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */

    public static byte[] sessionKeyByte;
    public static byte[] sessionIV;
    SessionEncrypter sessionEncrypter;
    SessionDecrypter sessionDecrypter;

    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */ 
    public ServerHandshake(Socket handshakeSocket, String cert, X509Certificate certCA, PrivateKey myKey) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
        sessionSocket = new ServerSocket(0);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();

        try {
            MessageDigest mdOut = MessageDigest.getInstance("SHA-256");
            MessageDigest mdIn = MessageDigest.getInstance("SHA-256");
            HandshakeMessage clientHello = new HandshakeMessage();
            clientHello.recv(handshakeSocket);
            clientHello.updateDigest(mdIn);

            assert clientHello.getParameter("MessageType").equals("ClientHello");
            //The server verifies the certificate, and sends its own cerficate in response:

            CertificateFactory factory = CertificateFactory.getInstance("X509");

            String String64_certUSR = clientHello.getParameter("Certificate");
            byte[] decoded64_certUSR = Base64.getDecoder().decode(String64_certUSR);
            X509Certificate certUSR = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decoded64_certUSR));

                VerifyCertificate.Verify(certCA, certUSR);
            HandshakeMessage serverHello = new HandshakeMessage();
            serverHello.putParameter("MessageType", "ServerHello");
            serverHello.putParameter("Certificate", cert);
            serverHello.updateDigest(mdOut);
            serverHello.send(handshakeSocket);

            //The client verifies the certificate, and proceeds by requesting port forwarding to the final destination (the target):
            HandshakeMessage forward = new HandshakeMessage();
            forward.recv(handshakeSocket);
            forward.updateDigest(mdIn);
            targetHost = forward.getParameter("TargetHost");
            targetPort = Integer.parseInt(forward.getParameter("TargetPort"));
            //If the server agrees to do port forwarding to the destination, it will set up the session.
            // For this, the server needs to generate a session key and initialisation vector. (with clients public key RSA) AES/CTR 128
            // Moreover, the server also creates a socket endpoint, and returns the corresponding TCP port number.
            sessionEncrypter = new SessionEncrypter(128);
            sessionKeyByte = sessionEncrypter.getKeyBytes();
            byte[] sessionKeyEncrypted = HandshakeCrypto.encrypt(sessionKeyByte,certUSR.getPublicKey());
            sessionIV = sessionEncrypter.getIVBytes();
            byte[] sessionIVEncrypted = HandshakeCrypto.encrypt(sessionIV,certUSR.getPublicKey());

            //set up the decrypter
            sessionDecrypter = new SessionDecrypter(sessionKeyByte,sessionIV);

            HandshakeMessage session = new HandshakeMessage();
            session.putParameter("MessageType", "Session");
            session.putParameter("SessionKey", new String(Base64.getEncoder().encode(sessionKeyEncrypted)));
            session.putParameter("SessionIV", new String(Base64.getEncoder().encode(sessionIVEncrypted)));
            session.putParameter("SessionHost", sessionHost);
            session.putParameter("SessionPort", String.valueOf(sessionPort));
            session.updateDigest(mdOut);
            session.send(handshakeSocket);

            //receive the clientfinish message
            HandshakeMessage clientFinish = new HandshakeMessage();
            clientFinish.recv(handshakeSocket);
            //get the current timestamp, decrypt the client one and compare them
            Timestamp ts = new Timestamp(new Date().getTime());
            byte[] clientTSByte = Base64.getDecoder().decode(clientFinish.getParameter("TimeStamp"));
            String clientTSString = new String(HandshakeCrypto.decrypt(clientTSByte, certUSR.getPublicKey()), StandardCharsets.UTF_8);
            Timestamp clientTS = Timestamp.valueOf(clientTSString);
            long d = ts.getTime()-clientTS.getTime();
            //decrypt the signatures, digest the messages, verify the signatures and timestamps
            byte[] clientSigByte = Base64.getDecoder().decode(clientFinish.getParameter("Signature"));
            byte[] clientSig = HandshakeCrypto.decrypt(clientSigByte, certUSR.getPublicKey());
            byte[] mdInBytes = mdIn.digest();
            byte[] mdBytes = mdOut.digest();

            if (!Arrays.equals(clientSig,mdInBytes)) {
                System.out.println("The client signature does not match - aborting handshake...");
                return;
            }
            else if (d > 1000 || d < -1000) {
                System.out.println("Timestamps are not identical - aborting handshake...");
                return;
            }

            HandshakeMessage serverFinish = new HandshakeMessage();
            //if everything was OK, send the serverFinished message
            serverFinish.putParameter("MessageType", "ServerFinished");

            byte[] mdEncrypted = HandshakeCrypto.encrypt(mdBytes,myKey);
            serverFinish.putParameter("Signature", new String(Base64.getEncoder().encode(mdEncrypted)));

            java.sql.Timestamp timestamp = new Timestamp(new Date().getTime());
            byte[] tsbytes = timestamp.toString().substring(0,19).getBytes(StandardCharsets.UTF_8);
            byte[] tsencr = HandshakeCrypto.encrypt(tsbytes,myKey);
            serverFinish.putParameter("TimeStamp", new String(Base64.getEncoder().encode(tsencr)));
            serverFinish.send(handshakeSocket);
            //When the ForwardClient receives the Session message, the handshake is completed.
            System.out.println("Forwarding to " + targetHost + ":" + targetPort);
            handshakeSocket.close();
        } catch (Exception e) {
            System.out.println("There was a problem during the handshake");
            e.printStackTrace();
            handshakeSocket.close();
            return;
        }
    }
}
