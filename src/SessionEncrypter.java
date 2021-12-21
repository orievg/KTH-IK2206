import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SessionEncrypter {

    private SessionKey key;
    private Cipher cipher;
    private IvParameterSpec iv;
    public SessionEncrypter(int keylength) throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.key = new SessionKey(keylength);
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        byte[] ivbytes = new byte[this.cipher.getBlockSize()];
        new SecureRandom().nextBytes(ivbytes);
        this.iv = new IvParameterSpec(ivbytes);
    }

    public SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.key = new SessionKey(keybytes);
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.iv = new IvParameterSpec(ivbytes);
    }

    byte[] getKeyBytes(){
        return this.key.getKeyBytes();
    }

    byte[] getIVBytes(){
        return this.iv.getIV();
    }
    CipherOutputStream openCipherOutputStream(OutputStream output) throws InvalidAlgorithmParameterException, InvalidKeyException {
        this.cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(),iv);
        CipherOutputStream stream = new CipherOutputStream(output, this.cipher);
        return stream;
    }
}
