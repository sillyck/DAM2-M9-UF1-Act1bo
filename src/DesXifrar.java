import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class DesXifrar {

	public static void main(String[] args) throws Exception {
	    String inputFile = "xifrat.txt";
	    String outputFile = "desxifrat.txt";
	    String keyFile = "clau.txt";
	    byte[] iv = new byte[8];

	    FileInputStream keyFileStream = new FileInputStream(keyFile);
	    ObjectInputStream keyInStream = new ObjectInputStream(keyFileStream);
	    SecretKey secretKey = (SecretKey) keyInStream.readObject();
	    String algorithm = (String) keyInStream.readObject();
	    byte[] encoded = (byte[]) keyInStream.readObject();
	    keyInStream.close();

	    KeySpec keySpec = new DESKeySpec(encoded);
	    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
	    SecretKey reconstructedKey = keyFactory.generateSecret(keySpec);

	    Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
	    FileInputStream ivStream = new FileInputStream(inputFile);
	    ivStream.read(iv);
	    ivStream.close();
	    desCipher.init(Cipher.DECRYPT_MODE, reconstructedKey, new IvParameterSpec(iv));

	    byte[] input = Files.readAllBytes(new File(inputFile).toPath());
	    byte[] output = desCipher.doFinal(input, 8, input.length - 8);

	    FileOutputStream outputFileStream = new FileOutputStream(outputFile);
	    outputFileStream.write(output);
	    outputFileStream.close();
	}
}