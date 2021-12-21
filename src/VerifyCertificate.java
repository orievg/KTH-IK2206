import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.Date;

public class VerifyCertificate {
    public static void Verify(X509Certificate ca, X509Certificate usr) throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        ca.verify(ca.getPublicKey());
        usr.verify(ca.getPublicKey());
        usr.checkValidity(new Date());
    }
    public static void Verify(String[] args) throws CertificateException, FileNotFoundException {
        if (args == null){
            System.out.println("Fail");
            System.out.println("No input specified");
            System.exit(1);
        }
        else if (args.length < 1){
            System.out.println("Fail");
            System.out.println("Two files are needed");
            System.exit(1);
        }
        FileInputStream fCA = new FileInputStream(args[0]);
        FileInputStream fUsr = new FileInputStream(args[1]);

        CertificateFactory factory = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(fCA);
        //System.out.println(cert.getIssuerX500Principal());

        CertificateFactory factoryU = CertificateFactory.getInstance("X509");
        X509Certificate certU = (X509Certificate) factoryU.generateCertificate(fUsr);
        //System.out.println(certU.getIssuerX500Principal());
    try{
        cert.verify(cert.getPublicKey());
        certU.verify(cert.getPublicKey());
        certU.checkValidity(new Date());
        System.out.println("Pass");
        //System.exit(0);
    } catch (NoSuchAlgorithmException e) {
        System.out.println("Fail");
        System.out.println("No such algorithm");
        e.printStackTrace();
    } catch (SignatureException e) {
        System.out.println("Fail");
        System.out.println("Signature not valid");
        e.printStackTrace();
    } catch (InvalidKeyException e) {
        System.out.println("Fail");
        System.out.println("Provided key is not valid");
        e.printStackTrace();
    } catch (NoSuchProviderException e) {
        System.out.println("Fail");
        System.out.println("The security provider is not valid");
        e.printStackTrace();
    }
    catch (CertificateExpiredException | CertificateNotYetValidException e) {
        System.out.println("Fail");
        System.out.println("Certificate is expired or not valid yet");
        e.printStackTrace();

    }
    }
}
