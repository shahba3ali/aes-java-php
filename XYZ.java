
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


//Demo Class
public class XYZ {

	private static final String AES_ALGORITHM = "AES";
	public static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
	public static final String UTF_8 = "UTF-8";
	public static final String PBKDF_SHA256 = "PBKDF2WithHmacSHA256";
	private static String salt = "ETYBDIJPOklskdfslakf";

	// channel specific security Configuration
	private String publickey;
	private String encrKey;
	private String encrHashSalt;

	public XYZ() {
		super();
	}

	public String encrypt(String value, int hashIterations) throws Exception {
	  System.out.println("---------------------step1 start-----------------");
	  System.out.println(" encrypt called with params ->"
	   + " password value: " + value + " hashIterations: " + hashIterations+ " " + value.getBytes());
		byte[] textEncrypted = null;
		String encryptedText = null;
		try {
			textEncrypted = encrypt(value.getBytes(), Cipher.ENCRYPT_MODE, hashIterations);
			System.out.println(" textEncrypted : " + textEncrypted);
			encryptedText = toHex(textEncrypted);
		} catch (Exception e) {
			throw e;
		} finally {
			textEncrypted = null;
		}
		System.out.println("---------------------step1 end-----------------");
		return encryptedText;
	}

	/**
	 * Hex converter method used for encryption
	 * 
	 * @param array
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	public String toHex(byte[] array) throws NoSuchAlgorithmException {
	  System.out.println("---------------------step4 start-----------------");
	  System.out.println("toHex called with params -> encryptedText byte array:" + array);
		BigInteger bi = null;
		String hex = null;
		int paddingLength = 0;
		try {
			bi = new BigInteger(1, array);
			hex = bi.toString(16);
			paddingLength = (array.length * 2) - hex.length();
			if (paddingLength > 0) {
				return String.format("%0" + paddingLength + "d", 0) + hex;
			} else {
			  System.out.println("output toHex: " + hex);
		    System.out.println("---------------------step4 end-----------------");
				return hex;
			}
		} finally {
			bi = null;
			hex = null;
		}
		
	}

	/**
	 * Returns the encrypted result of the input value
	 * 
	 * @param value
	 * @param opmode
	 * @return
	 */
	public byte[] encrypt(byte[] value, int opmode, int hashIterations) throws Exception {
	  System.out.println("---------------------step2 start-----------------");
	  System.out.println(" encrypt overloaded called with params -> "
	  + " password byte value: " + value + " opmode:" + opmode + " hashIterations:" + hashIterations);
	  
		IvParameterSpec iv = new IvParameterSpec("encryptionIntVec".getBytes(UTF_8));

        System.out.println("IvParameterSpec iv       "+iv);

		SecretKeySpec secretKey = null;
		Cipher desCipher = null;
		byte[] textEncrypted = null;
		try {
			// commented by shahbaz using secretkey "encryptionIntVec"
			//secretKey = createKeySpec(getEncrKey(), hashIterations);
			secretKey = new SecretKeySpec("encryptionIntVec".getBytes(), "AES");
			desCipher = Cipher.getInstance(TRANSFORMATION);
			System.out.println("---Cipher creation starts--");
			System.out.println("opmode: " + opmode);
			System.out.println("secretKey: " + secretKey.getEncoded());
			System.out.println(" iv: " +  iv.getIV());
			desCipher.init(opmode, secretKey, iv);
			textEncrypted = desCipher.doFinal(value);
			String encodedKey = Base64.getEncoder().encodeToString(textEncrypted);
			System.out.println("textEncrypted shahbaz base64: " + encodedKey);
		} catch (Exception e) {
			throw e;
		} finally {
			secretKey = null;
			desCipher = null;
		}
		System.out.println("---------------------step2 end-----------------");
		return textEncrypted;
	}

	/**
	 * @param myKey
	 * @return
	 */
	public SecretKeySpec createKeySpec(String myKey, int hashIterations) throws Exception {
    System.out.println("---------------------step3 start-----------------");
    //System.out.println("createKeySpec called with params -> encryptionkey:" + myKey
    //+ " hashIterations:" + hashIterations);
    
		SecretKeyFactory factory = null;
		KeySpec spec = null;
		SecretKey tmp = null;
		SecretKeySpec secretKey = null;
		factory = SecretKeyFactory.getInstance(PBKDF_SHA256);
		System.out.println("myKey toCharArray: " + myKey.toCharArray());
		System.out.println("salt bytes: " + salt.getBytes());
		System.out.println("key length: " + 128);
		spec = new PBEKeySpec(myKey.toCharArray(), salt.getBytes(), hashIterations, 128);
		tmp = factory.generateSecret(spec);
		secretKey = new SecretKeySpec(tmp.getEncoded(), AES_ALGORITHM);
           String str = new String(tmp.getEncoded(), UTF_8);

    System.out.println("output secretKey String: " +  str);
    System.out.println("output secretKey OB: " +  secretKey.getEncoded());
    System.out.println("---------------------step3 start-----------------");


	String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
	System.out.println("output encodedKey " + encodedKey);
		return secretKey;
	}

	//Updated for Demo Class
	public int getHashingIterationCount() {
		int iterationCount = 100;
		return iterationCount;
	}

	/**
	 * @return the publickey
	 */
	public String getPublickey() {
		return publickey;
	}

	/**
	 * @param publickey the publickey to set
	 */
	public void setPublickey(String publickey) {
		this.publickey = publickey;
	}

	/**
	 * @return the encrKey
	 */
	public String getEncrKey() {
		return encrKey;
	}

	/**
	 * @param encrKey the encrKey to set
	 */
	public void setEncrKey(String encrKey) {
		this.encrKey = encrKey;
	}

	/**
	 * @return the encrHashSalt
	 */
	public String getEncrHashSalt() {
		return encrHashSalt;
	}

	/**
	 * @param encrHashSalt the encrHashSalt to set
	 */
	public void setEncrHashSalt(String encrHashSalt) {
		this.encrHashSalt = encrHashSalt;
	}

	public static void main(String args[]) {
		XYZ securityFactory = new XYZ();
		securityFactory.setEncrKey("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");
		try {
			String encrypt = securityFactory.encrypt("2296", 100);
			System.out.println("ENCR::" + encrypt);
		} catch (Exception e) {
		System.out.println("exception");
			e.printStackTrace();
		}
	}

}