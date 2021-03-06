/*
 * Copyright 2017 Michael Mitchell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cryptoUtils;

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

/*
 * Description: A simple utility class for PBE AES and DESede
 */

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

    // 5-arg constructor
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

        // Make sure the algorithm entered is an algorithm the class can use
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

        // See if the algorithm is entered before trying to derive the algo spec
        if (this.algorithm == null) {
            return flag;
        }

        // Verify that the algo spec entered is based from the algorithm
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

        // Verify that the key strength entered is valid for the algorithm
        if (algorithm.contains(acceptableAlgoSpecs[0])){
            if (keyStrength == acceptableKeyStrengths[0] || keyStrength == acceptableKeyStrengths[2]) {
                this.keyStrength = keyStrength;
                return true;
            }

            else {
                return false;

            }
        }

        // Verify that the key strength entered is valid for the algorithm
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

        // Test to see if all the variables are initialized and ready for operation
        if (algorithm == null || algoSpec == null
                || password == null || keyStrength == null || cipherMode == null)

            return false;

        return true;
    }

    // Test the files to see if the are writable and readable for encryption/ decription
    private void encryptDecryptReady(File inputFile, File outputFile) throws IOException {

        if (!isReady() || inputFile == null || outputFile == null)
            throw new IllegalArgumentException("Required parameters not initialized");

        if (!inputFile.canRead())
            throw new NoSuchFileException("Could not find file: " + inputFile.toString());

        if (!outputFile.exists()) {
            if (!outputFile.createNewFile())
                throw new IOException("Could not create file: " + outputFile.toString());

            outputFile.delete();

        }
        else if (!outputFile.canWrite()) {
            throw new IOException("Could not write to file: " + outputFile.toString());

        }

    }

    // Initialize the cipher for the user-selected operation
    public Cipher getInitializedCipher() throws InvalidKeySpecException, NoSuchAlgorithmException,
                                         NoSuchPaddingException, InvalidParameterSpecException,
                                         InvalidKeyException, InvalidAlgorithmParameterException {

        // Check that all the fields are filled out before trying to make a cipher
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

    // Do an encryption cycle with the cipher provided from the above method
    public boolean doEncryption(Cipher cipher, File inputFile, File outputFile) throws IOException {

        // Test to see if the files are readable/ writable etc.
        encryptDecryptReady(inputFile, outputFile);
        outputFile.createNewFile();

        /*
         * While the password is indeed padded, the form of encryption intended
         * to be use with this utility class requires padding the file manually
         * to ensure the actual contents of the file are not corrupted/ forgotten
         * to be decrypted. To avoid this, we pad the file loosely based on the
         * length of the password (There is no way to tell the length of the
         * password from the encrypted data) as there appears to be a direct correlation
         * between the length of the password and the amount of bits left
         * corrupted/ not decrypted on a decryption process.
         */
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

        // Read in the file
        inputStream.read(fileBytes, remainingLength, (int) inputFile.length());

        streamType = new FileOutputStream(outputFile);
        BufferedOutputStream outStreamType = new BufferedOutputStream((FileOutputStream) streamType);

        // Make a CipherOutputStream to encrypt and write the file at the same time
        CipherOutputStream outputStream = new CipherOutputStream(outStreamType, cipher);

        // Write, close, and flush the output stream
        outputStream.write(fileBytes);
        outputStream.flush();
        outputStream.close();

        // Return successful operation;
        return true;

    }

    // Do an decryption cycle with the cipher provided from the getInitializedCipher method
    public boolean doDecryption(Cipher cipher, File inputFile, File outputFile) throws IOException,
                                                                                IllegalBlockSizeException,
                                                                                BadPaddingException {

        // Test to see if the files are readable/ writable etc.
        encryptDecryptReady(inputFile, outputFile);
        outputFile.createNewFile();

        /*
         * While the password is indeed padded, the form of encryption intended
         * to be use with this utility class requires padding the file manually
         * to ensure the actual contents of the file are not corrupted/ forgotten
         * to be decrypted. To avoid this, we pad the file loosely based on the
         * length of the password (There is no way to tell the length of the
         * password from the encrypted data) as there appears to be a direct correlation
         * between the length of the password and the amount of bits left
         * corrupted/ not decrypted on a decryption process.
         */
        int remainingLength = 16;

        if (this.password.length() < remainingLength) {
            remainingLength = remainingLength + password.length();

        }

        Object streamType = new FileInputStream(inputFile);
        BufferedInputStream inputStream = new BufferedInputStream((FileInputStream) streamType);

        byte[] fileBytes = new byte[(int) inputFile.length()];

        // Read in the file
        inputStream.read(fileBytes);

        // Decrypt the file
        byte[] decryptedFile = cipher.doFinal(fileBytes);

        streamType = new FileOutputStream(outputFile);
        BufferedOutputStream outputStream = new BufferedOutputStream((FileOutputStream) streamType);

        // Write out the neccessary parts of the file
        // (the file - the padding)
        outputStream.write(decryptedFile, remainingLength, decryptedFile.length - remainingLength);
        outputStream.flush();
        outputStream.close();

        // Return successful operation
        return true;

    }

}
