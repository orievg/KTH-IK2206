/**
 * Client side of the handshake.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.net.Socket;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

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
        MessageDigest mdOut = MessageDigest.getInstance("SHA-256");
        MessageDigest mdIn = MessageDigest.getInstance("SHA-256");
        //The first message is where the client introduces itself to the server:
        HandshakeMessage clientHello = new HandshakeMessage();
        clientHello.putParameter("MessageType", "ClientHello");
        clientHello.putParameter("Certificate", Cert);
        clientHello.updateDigest(mdOut);
        clientHello.send(handshakeSocket);
        //The server verifies the certificate, and sends its own cerficate in response
        // So we wait for the message here

        HandshakeMessage serverHello = new HandshakeMessage();
        serverHello.recv(handshakeSocket);
        serverHello.updateDigest(mdIn);
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
        forward.updateDigest(mdOut);
        forward.send(handshakeSocket);

        //If the server agrees to do port forwarding to the destination, it will set up the session.
        //For this, the server needs to generate a session key and initialisation vector.
        //Moreover, the server also creates a socket endpoint, and returns the corresponding TCP port number.
        HandshakeMessage session = new HandshakeMessage();
        session.recv(handshakeSocket);
        session.updateDigest(mdIn);
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

        //Start new clientFinish message
        HandshakeMessage clientFinish = new HandshakeMessage();
        clientFinish.putParameter("MessageType", "ClientFinished");
        //complete digests and put one in the signature field
        byte[] mdBytes = mdOut.digest();
        byte[] mdInBytes = mdIn.digest();
        byte[] mdEncrypted = HandshakeCrypto.encrypt(mdBytes,myKey);
        clientFinish.putParameter("Signature", new String(Base64.getEncoder().encode(mdEncrypted)));

        //get the current timestamp, format it, encrypt and witht the message
        Timestamp timestamp = new Timestamp(new Date().getTime());
        byte[] tsbytes = timestamp.toString().substring(0,19).getBytes(StandardCharsets.US_ASCII);
        byte[] tsencr = HandshakeCrypto.encrypt(tsbytes,myKey);
        clientFinish.putParameter("TimeStamp", new String(Base64.getEncoder().encode(tsencr)));
        clientFinish.send(handshakeSocket);

        //receive the serverFinish message
        HandshakeMessage serverFinish = new HandshakeMessage();
        serverFinish.recv(handshakeSocket);
        //get the current timestamp and decrypt the server one and compare them
        timestamp = new Timestamp(new Date().getTime());
        byte[] serverTSByte = Base64.getDecoder().decode(serverFinish.getParameter("TimeStamp"));
        String serverTSString = new String(HandshakeCrypto.decrypt(serverTSByte, certS.getPublicKey()), StandardCharsets.UTF_8);
        Timestamp serverTS = Timestamp.valueOf(serverTSString);
        long d = timestamp.getTime() - serverTS.getTime();

        //decrypt the signature
        byte[] serverSigByte = Base64.getDecoder().decode(serverFinish.getParameter("Signature"));
        byte[] serverSig = HandshakeCrypto.decrypt(serverSigByte, certS.getPublicKey());
        //if the timestamps or signatures do not match, cancel the handshake
        if (!Arrays.equals(serverSig, mdInBytes)) {
            System.out.println("The client signature does not match - aborting handshake...");
            System.exit(1);
        }
        else if (d > 1000 || d < -1000) {
            System.out.println("Timestamps are not identical - aborting handshake...");
            System.exit(1);
        }
        handshakeSocket.close();

    }
}
