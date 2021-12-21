/**
 * Client side of the handshake.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.net.Socket;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    
    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort = 12345;




    /* Security parameters key/iv should also go here. Fill in! */

    public static byte[] sessionKeyByte;
    SessionKey sessionKey;
    public static byte[] sessionIV;
    SessionEncrypter sessionEncrypter = null;
    SessionDecrypter sessionDecrypter = null;

    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now.
     * @return
     */ 
    public ClientHandshake(Socket handshakeSocket, String Cert, X509Certificate certCA, String targethost, String targetport, PrivateKey myKey) throws IOException, CertificateException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, SignatureException, NoSuchProviderException {
        //The first message is where the client introduces itself to the server:
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter("MessageType", "ClientHello");
        clientHello.putParameter("Certificate", Cert);
        clientHello.send(handshakeSocket);

        //The server verifies the certificate, and sends its own cerficate in response
        // So we wait for the message here

        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(handshakeSocket);
        //Exctract the certificate and verify it.
        String String64_certSRV;
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        String64_certSRV = serverHello.getParameter("Certificate");
        byte[] decoded64_certSRV = Base64.getDecoder().decode(String64_certSRV);
        X509Certificate certS = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decoded64_certSRV));
        VerifyCertificate.Verify(certCA,certS);
        //The client verifies the certificate, and proceeds by requesting port forwarding to the final destination (the target):
        HandshakeMessage forward = new HandshakeMessage();
        forward.putParameter("MessageType", "Forward");
        forward.putParameter("TargetHost", targethost);
        forward.putParameter("TargetPort", targetport);
        forward.send(handshakeSocket);

        //If the server agrees to do port forwarding to the destination, it will set up the session.
        //For this, the server needs to generate a session key and initialisation vector.
        //Moreover, the server also creates a socket endpoint, and returns the corresponding TCP port number.
        HandshakeMessage session = new HandshakeMessage();
        session.recv(handshakeSocket);

        //read and decode params
        assert session.getParameter("MessageType").equals("Session") : "NOT SESSION MSG";
        byte[] e_sessionKey = Base64.getDecoder().decode(session.getParameter("SessionKey"));
        sessionKeyByte = HandshakeCrypto.decrypt(e_sessionKey, myKey);
        sessionKey = new SessionKey(sessionKeyByte);

        byte[] e_sessionIV = Base64.getDecoder().decode(session.getParameter("SessionIV"));
        sessionIV = HandshakeCrypto.decrypt(e_sessionIV, myKey);

        sessionHost = session.getParameter("SessionHost");
        sessionPort = Integer.parseInt(session.getParameter("SessionPort"));

        //When the ForwardClient receives the Session message, the handshake is completed.
        this.sessionEncrypter = new SessionEncrypter(sessionKeyByte, sessionIV);
        this.sessionDecrypter = new SessionDecrypter(sessionKeyByte,sessionIV);
        handshakeSocket.close();

    }
}
