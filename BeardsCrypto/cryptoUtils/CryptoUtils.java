package BeardsCrypto.cryptoUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.NoSuchFileException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

public class CryptoUtils {

    // Private fields
    private byte[] salt = {((byte)69), ((byte)43), ((byte)-103),
                            ((byte)-10), ((byte)5), ((byte)-26),
                            ((byte)-98), ((byte)77)};

    private String[] acceptableAlgorithms = {"AES/CBC/PKCS5Padding", "DESede/CBC/PKCS5Padding"},
                     acceptableAlgoSpecs = {"AES", "DESede"};

    private int[] acceptableKeyStrengths = {128, 192, 256};

    private String algorithm,
                   algoSpec,
                   password;

    private Integer keyStrength,
                    iterations = 65536,
                    cipherMode;

    // Constructors
    public CryptoUtils() {
        this.cipherMode = null;
        this.password = null;
        this.algorithm = null;
        this.algoSpec = null;
        this.keyStrength = null;

    }

    public CryptoUtils(String password, Integer cipherMode, String algorithm,
                       String algoSpec, Integer keyStrength) {

        setPassword(password);
        setCipherMode(cipherMode);
        setAlgorithm(algorithm);
        setAlgoSpec(algoSpec);
        setKeyStrength(keyStrength);

    }

    // Mutators
    public boolean setCipherMode(Integer cipherMode) {
        if (cipherMode == Cipher.DECRYPT_MODE || cipherMode == Cipher.ENCRYPT_MODE) {
            this.cipherMode = cipherMode;
            return true;

        }

        return false;

    }

    public void setPassword(String password) {
        this.password = password;

    }

    public boolean setAlgorithm(String algorithm){
        boolean flag = false;

        for (String algo : acceptableAlgorithms) {
            if (algorithm.equals(algo)) {
                this.algorithm = algorithm;
                flag = true;

            }
        }

        return flag;

    }

    public boolean setAlgoSpec(String algoSpec) {
        boolean flag = false;

        if (this.algorithm == null) {
            return flag;
        }

        for (String algo : acceptableAlgoSpecs) {
            if (algoSpec.equals(algo)) {
                if (algorithm.contains(algoSpec)) {
                    this.algoSpec = algoSpec;
                    flag = true;

                }
            }
        }

        return flag;
    }

    public boolean setKeyStrength(int keyStrength) {

        if (this.algorithm == null)
            return false;

        if (algorithm.contains(acceptableAlgoSpecs[0])){
            if (keyStrength == acceptableKeyStrengths[0] || keyStrength == acceptableKeyStrengths[2]) {
                this.keyStrength = keyStrength;
                return true;
            }

            else {
                return false;

            }
        }

        if (algorithm.contains(acceptableAlgoSpecs[1])) {
            if (keyStrength == acceptableKeyStrengths[1]) {
                this.keyStrength = keyStrength;
                return true;
            }

            else {
                return false;

            }
        }

        return false;

    }

    // Accessors
    public Integer getCipherMode() {
        return this.cipherMode;

    }

    public String getPassword() {
        return this.password;

    }

    public String getAlgorithm() {
        return this.algorithm;

    }

    public String getAlgoSpec() {
        return this.algoSpec;

    }

    public Integer getKeyStrength() {
        return this.keyStrength;

    }

    // General functions
    public boolean isReady() {

        if (algorithm == null || algoSpec == null
                || password == null || keyStrength == null || cipherMode == null)

            return false;

        return true;
    }

    private void encryptDecryptReady(File inputFile, File outputFile) throws IOException {

        if (!isReady() || inputFile == null || outputFile == null)
            throw new IllegalArgumentException("Required parameters not initialized");

        if (!inputFile.canRead())
            throw new NoSuchFileException("Could not find file: " + inputFile.toString());

        if (!outputFile.exists()) {
            if (!outputFile.createNewFile())
                throw new IOException("Could not create file: " + outputFile.toString());

        }

        else if (!outputFile.canWrite()) {
            throw new IOException("Could not write to file: " + outputFile.toString());

        }

    }

    public Cipher getInitializedCipher() throws InvalidKeySpecException, NoSuchAlgorithmException,
                                         NoSuchPaddingException, InvalidParameterSpecException,
                                         InvalidKeyException, InvalidAlgorithmParameterException {

        if (!isReady())
            throw new IllegalArgumentException("Required parameters not initialized");

        Cipher cipher;

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        KeySpec spec = new PBEKeySpec(this.password.toCharArray(), this.salt,
                                      this.iterations, this.keyStrength);

        SecretKey tmp = factory.generateSecret(spec);

        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), this.algoSpec);

        cipher = Cipher.getInstance(this.algorithm);

        AlgorithmParameters params = cipher.getParameters();

        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

        cipher.init(this.cipherMode, secret, new IvParameterSpec(iv));

        return cipher;

    }

    public boolean doEncryption(Cipher cipher, File inputFile, File outputFile) throws IOException {

        try {
            encryptDecryptReady(inputFile, outputFile);

        } catch (IOException readyException) {
            System.out.print(readyException.getMessage());
            readyException.printStackTrace(System.out);
            return false;

        }

        int remainingLength = 16;

        if (this.password.length() < remainingLength) {
            remainingLength = remainingLength + password.length();

        }

        Object streamType = new FileInputStream(inputFile);
        BufferedInputStream inputStream = new BufferedInputStream((FileInputStream) streamType);

        byte[] fileBytes = new byte[(int) inputFile.length() + remainingLength];

        for (int count = 0; count <= remainingLength; count++) {
            fileBytes[count] = (byte) 11;

        }

        inputStream.read(fileBytes, remainingLength, (int) inputFile.length());

        streamType = new FileOutputStream(outputFile);
        BufferedOutputStream outStreamType = new BufferedOutputStream((FileOutputStream) streamType);

        CipherOutputStream outputStream = new CipherOutputStream(outStreamType, cipher);

        outputStream.write(fileBytes);
        outputStream.flush();
        outputStream.close();

        return true;

    }

    public boolean doDecryption(Cipher cipher, File inputFile, File outputFile) throws IOException,
                                                                                IllegalBlockSizeException,
                                                                                BadPaddingException {

        try {
            encryptDecryptReady(inputFile, outputFile);

        } catch (IOException readyException) {
            System.out.print(readyException.getMessage());
            readyException.printStackTrace(System.out);
            return false;

        }

        int remainingLength = 16;

        if (this.password.length() < remainingLength) {
            remainingLength = remainingLength + password.length();

        }

        Object streamType = new FileInputStream(inputFile);
        BufferedInputStream inputStream = new BufferedInputStream((FileInputStream) streamType);

        byte[] fileBytes = new byte[(int) inputFile.length()];

        inputStream.read(fileBytes);

        byte[] decryptedFile = cipher.doFinal(fileBytes);

        streamType = new FileOutputStream(outputFile);
        BufferedOutputStream outputStream = new BufferedOutputStream((FileOutputStream) streamType);

        outputStream.write(decryptedFile, remainingLength, decryptedFile.length - remainingLength);
        outputStream.flush();
        outputStream.close();

        return true;

    }

}
