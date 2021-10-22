package ch.zhaw.its.lab.secretkey;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.plaf.SpinnerUI;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLOutput;
import java.util.HashMap;
import java.util.Map;

public class entropy {
    public static final String KALGORITHM = "AES";
    public static final String CALGORITHM = KALGORITHM + "/CBC/PKCS5Padding";
    private static String inFile = "./itsec-secret-key-crypto/mystery";
    private static String outFile = "./decrypted";
    static byte[] key = new byte[16];

    private static void crypt(FileInputStream is, FileOutputStream os, Cipher cipher) throws IOException, BadPaddingException, IllegalBlockSizeException {
        boolean more = true;
        byte[] input = new byte[cipher.getBlockSize()];

        while (more) {
            int inBytes = is.read(input);

            if (inBytes > 0) {
                os.write(cipher.update(input, 0, inBytes));
            } else {
                more = false;
            }
        }
        os.write(cipher.doFinal());
    }
    /*
    public void encrypt() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        KeyGenerator keyGen = KeyGenerator.getInstance(KALGORITHM);
        keyGen.init(128, new TotallySecureRandom());
        SecretKey key = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance(CALGORITHM);

        byte[] rawIv = new byte[cipher.getBlockSize()];
        new TotallySecureRandom().nextBytes(rawIv);
        IvParameterSpec iv = new IvParameterSpec(rawIv);

        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        try (InputStream is = new FileInputStream(inFile);
             OutputStream os = new FileOutputStream(outFile)) {
            writeIv(os, iv);
            crypt(is, os, cipher);
        }
    }*/

    private static IvParameterSpec readIv(InputStream is, Cipher cipher) throws IOException {
        byte[] rawIv = new byte[cipher.getBlockSize()];
        int inBytes = is.read(rawIv);

        if (inBytes != cipher.getBlockSize()) {
            throw new IOException("can't read IV from file");
        }

        return new IvParameterSpec(rawIv);
    }

    public void writeIv(OutputStream os, IvParameterSpec iv) throws IOException {
        os.write(iv.getIV());
    }

    public static void decrypt(byte[] rawKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException,
            BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        SecretKey key = new SecretKeySpec(rawKey, 0, rawKey.length, KALGORITHM);
        Cipher cipher = Cipher.getInstance(CALGORITHM);

        try (FileInputStream is = new FileInputStream(inFile);
             FileOutputStream os = new FileOutputStream(outFile)) {
            IvParameterSpec ivParameterSpec = readIv(is, cipher);

            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
            crypt(is, os, cipher);
        }
    }

    public static double logBase2(double x) {
        return Math.log10(x)/Math.log10(2);

    }
    public static double getEntropy(byte[] data) throws IOException {
        HashMap<Byte, Integer> charCount = new HashMap<>();
        byte [] bytes = data;
         for (byte c : bytes) {
             if(charCount.containsKey(c)) {
                 charCount.replace(c, charCount.get(c) + 1);
             } else {
                 charCount.put(c, 1);
             }
        }
        double sum = 0;
        for (double v : charCount.values()) {
            double fk = (v/bytes.length);
            sum = sum + (fk*logBase2(fk));
        }

        return sum*-1   ;
    }
    public static void updateKey(){
        for(int i=0;i<key.length;i++)
        if(key[i] <= -128) {
            key[i+1]--;
            return;
        } else {
            key[i]--;
            return;
        }
    }
    public static void main(String[] args) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Path path = Paths.get(inFile);
        byte[] cipherText = Files.readAllBytes(path);
        for (int i=0; i <16; i++) { // Set iv to key
            key[i] = cipherText[i];
        }
        int runs =1;
        try {
            decrypt(key);
        } catch (Exception BadPaddingException) {

        }
        while(getEntropy(Files.readAllBytes(Paths.get(outFile)))>5) {
            System.out.println(runs);
            updateKey();
            try{decrypt(key);} catch (Exception BadPAddingException){}
            runs++;
        }
        System.out.println("found key:");
        for (byte b : key){
            System.out.printf(b+" ");
        }
        /*
        inputs = new String [] {
                "C:\\Users\\nicol\\Documents\\github\\ITS\\Lab2\\itsec-secret-key-crypto\\mystery",
                "C:\\Users\\nicol\\Documents\\github\\ITS\\Lab2\\itsec-secret-key-crypto\\src\\main\\java\\ch\\zhaw\\its\\lab\\secretkey\\FileEncrypter.java"
        };
        Path p = Paths.get(inputs[0]);
        byte[] t = Files.readAllBytes(p);
        getEntropy(t);
        Path p2 = Paths.get(inputs[1]);
        byte[] t2 = Files.readAllBytes(p2);

        System.out.println(getEntropy(t));
        System.out.println(getEntropy(t2));
         */
    }
}
