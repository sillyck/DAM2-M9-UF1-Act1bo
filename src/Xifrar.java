import java.io.File;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Xifrar {

	public static void main(String[] args) throws Exception {
	    String inputFile = "missatge.txt";
	    String outputFile = "xifrat.txt";
	    String keyFile = "clau.txt";
	    SecretKey secretKey = null;
	    byte[] iv = new byte[8];
	    KeyGenerator keyGen = KeyGenerator.getInstance("DES");
	    SecureRandom random = new SecureRandom();
	    secretKey = keyGen.generateKey();

	    FileOutputStream keyFileStream = new FileOutputStream(keyFile);
	    ObjectOutputStream keyOutStream = new ObjectOutputStream(keyFileStream);
	    keyOutStream.writeObject(secretKey);
	    keyOutStream.writeObject(secretKey.getAlgorithm());
	    keyOutStream.writeObject(secretKey.getEncoded());
	    keyOutStream.close();

	    Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
	    random.nextBytes(iv);
	    desCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

	    byte[] input = Files.readAllBytes(new File(inputFile).toPath());

	    int paddingLength = 8 - (input.length % 8);
	    byte[] paddedInput = new byte[input.length + paddingLength];
	    System.arraycopy(input, 0, paddedInput, 0, input.length);

	    byte[] output = desCipher.doFinal(paddedInput);

	    byte[] outputWithIV = new byte[iv.length + output.length];
	    System.arraycopy(iv, 0, outputWithIV, 0, iv.length);
	    System.arraycopy(output, 0, outputWithIV, iv.length, output.length);

	    FileOutputStream outputFileStream = new FileOutputStream(outputFile);
	    outputFileStream.write(outputWithIV);
	    outputFileStream.close();
	}
}