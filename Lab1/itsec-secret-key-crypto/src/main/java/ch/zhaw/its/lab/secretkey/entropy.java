package ch.zhaw.its.lab.secretkey;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class entropy {
    public static double logBase2(double x) {
        return Math.log10(x)/Math.log10(2);

    }
    public static double getEntropy(String file) throws IOException {

        long length = (new File(file).length());
        HashMap<Character, Integer> charCount = new HashMap<>();
        BufferedReader reader = new BufferedReader(new FileReader(file));
        while (reader.ready()) {
            char c = (char) reader.read();
            if (charCount.containsKey(c)) {
                charCount.put(c, charCount.get(c) + 1);
            } else {
                charCount.put(c, 1);
            }
        }
        double sum = 0;
        for (double v : charCount.values()) {
            double fk = (v/length);
            sum = sum + (fk*logBase2(fk));
        }

        return sum*-1   ;
    }
    public static void main(String[] args) throws IOException {
        //byte[] text = args[1];
        //byte[] cipher = args[2];
    String file1 = "C:\\Users\\nicol\\Documents\\GitHub\\itsec-secret-key-crypto\\mystery";


    String file2 = "C:\\Users\\nicol\\Documents\\GitHub\\itsec-secret-key-crypto\\src\\main\\java\\ch\\zhaw\\its\\lab\\secretkey\\FileEncrypter.java";

        System.out.println(getEntropy(file1));
        System.out.println(getEntropy(file2));

    }
}
