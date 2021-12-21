import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class SessionKey {
    private SecretKey secretKey;

    public SessionKey(int keylength) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keylength);
        this.secretKey = keyGen.generateKey();
    }


    public SessionKey(byte[] keybytes) {
        this.secretKey = new SecretKeySpec(keybytes, "AES");
    }


    SecretKey getSecretKey(){
        return this.secretKey;
    }


    byte[] getKeyBytes(){
        return this.secretKey.getEncoded();
    }
}
