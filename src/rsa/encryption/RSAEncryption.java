package rsa.encryption;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Random;

public class RSAEncryption {

    public static BigInteger priv = null;

    public static void main(String[] args) throws IOException {

        // generate data
        if (args[0].equalsIgnoreCase("g")) {
            RSAUtilities CompanyA = new RSAUtilities(Integer.parseInt(args[1]));

            BigInteger[] publicKeyCompanyA = CompanyA.getPublicKey(Integer.parseInt(args[1]));

            BigInteger privateKeyCompanyA = CompanyA.getPrivateKey(publicKeyCompanyA[0], CompanyA.phi);

            // write public key
            File pubkey = new File(args[2]);
            BufferedWriter writer0 = new BufferedWriter(new FileWriter(pubkey));
            writer0.write(publicKeyCompanyA[0].toString());
            writer0.close();
            // write mobulus
            File modulus = new File(args[3]);
            BufferedWriter writer1 = new BufferedWriter(new FileWriter(modulus));
            writer1.write(publicKeyCompanyA[1].toString());
            writer1.close();

            // write private key
            File privkey = new File(args[4]);
            BufferedWriter writer2 = new BufferedWriter(new FileWriter(privkey));
            writer2.write(privateKeyCompanyA.toString());
            writer2.close();
            return;
        }

        if (args[0].equalsIgnoreCase("e")) {
            String line = "", result = "", dmessage;

            File pubkeyFile = new File(args[1]);
            File modulusFile = new File(args[2]);
            File privkeyFile = new File(args[3]);
            File dmessageFile = new File(args[4]);

            BufferedReader pubkeyreader = new BufferedReader(new FileReader(pubkeyFile));
            BufferedReader privkeyreader = new BufferedReader(new FileReader(privkeyFile));
            BufferedReader modulusreader = new BufferedReader(new FileReader(modulusFile));
            BufferedReader dmessagereader = new BufferedReader(new FileReader(dmessageFile));

            // read message to decrypt key
            while ((line = dmessagereader.readLine()) != null) {
//                System.out.println(line);
                result += line + "\n";
            }
            dmessage = result;
            result = "";
            line = "";
//            System.out.println(dmessage);

            // read publick key
            while ((line = pubkeyreader.readLine()) != null) {
                result += line;
            }
            BigInteger publicKey = new BigInteger(result);
            line = "";
            result = "";

            // read modulusFile
            while ((line = modulusreader.readLine()) != null) {
                result += line;
            }
            BigInteger modulusKey = new BigInteger(result);
            line = "";
            result = "";

            // read private key
            while ((line = privkeyreader.readLine()) != null) {
                result += line;
            }
            BigInteger privateKey = new BigInteger(result);
            line = "";
            result = "";
            priv = privateKey;

            BigInteger[] PubModulus = new BigInteger[2];
            PubModulus[0] = publicKey;
            PubModulus[1] = modulusKey;

//            System.out.println("publicKey is \n" + publicKey + "\n");
//            System.out.println("modulusKey is \n" + modulusKey + "\n");
//            System.out.println("privateKey is \n" + privateKey + "\n");
            System.out.println(new RSAUtilities().encrypt(dmessage, PubModulus));

            return;
        }

        if (args[0].equalsIgnoreCase("d")) {
            String line = "", result = "";

            File pubkeyFile = new File(args[1]);
            File modulusFile = new File(args[2]);
            File privkeyFile = new File(args[3]);
            File emessageFile = new File(args[4]);

            BufferedReader pubkeyreader = new BufferedReader(new FileReader(pubkeyFile));
            BufferedReader privkeyreader = new BufferedReader(new FileReader(privkeyFile));
            BufferedReader modulusreader = new BufferedReader(new FileReader(modulusFile));
            BufferedReader emessagereader = new BufferedReader(new FileReader(emessageFile));

            // read publick key
            while ((line = pubkeyreader.readLine()) != null) {
                result += line;
            }
            BigInteger publicKey = new BigInteger(result);
            line = "";
            result = "";

            // read modulusFile
            while ((line = modulusreader.readLine()) != null) {
                result += line;
            }
            BigInteger modulusKey = new BigInteger(result);
            line = "";
            result = "";

            // read private key
            while ((line = privkeyreader.readLine()) != null) {
                result += line;
            }
            BigInteger privateKey = new BigInteger(result);
            line = "";
            result = "";

            // read encrypted message
            while ((line = emessagereader.readLine()) != null) {
                result += line;
            }
            BigInteger emsg = new BigInteger(result);
            line = "";
            result = "";

            BigInteger[] PubModulus = new BigInteger[2];
            PubModulus[0] = publicKey;
            PubModulus[1] = modulusKey;

            if (System.getProperty("os.name").toLowerCase().indexOf("windows") != -1) {
                System.out.println(new String(new RSAUtilities().decrypt(emsg, privateKey, PubModulus).getBytes(Charset.forName("cp866"))));
            } else {
                System.out.println(new RSAUtilities().decrypt(emsg, privateKey, PubModulus));
            }
            return;
        }
    }
}

class RSAUtilities {

    BigInteger p, q, n, phi = null, d, e;
    StringHexUtil hexutil = new StringHexUtil();

    public static String toHexString(byte[] ba) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < ba.length; i++) {
            str.append(String.format("%x", ba[i]));
        }
        return str.toString();
    }

    public static String fromHexString(String hex) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            str.append((char) Integer.parseInt(hex.substring(i, i + 2), 16));
        }
        return str.toString();
    }

    // convert from UTF-8 -> internal Java String format
    public static String convertFromUTF8(String s) {
        String out = null;
        try {
            out = new String(s.getBytes("ISO-8859-1"), "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return null;
        }
        return out;
    }

    // convert from internal Java String format -> UTF-8
    public static String convertToUTF8(String s) {
        String out = null;
        try {
            out = new String(s.getBytes("UTF-8"), "ISO-8859-1");
        } catch (java.io.UnsupportedEncodingException e) {
            return null;
        }
        return out;
    }

    public RSAUtilities() {
    }

    public RSAUtilities(int bit) {
        p = getBigIntPrime(bit); // p ( first prime number )
        q = getBigIntPrime(bit); // q ( second prime number )
        n = p.multiply(q); // n=p⋅q ( Modulus )
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // ϕ(n)=(p−1)⋅(q−1) ( Totient )
    }

    public BigInteger[] getPublicKey(int bit) {
        return new BigInteger[]{getBigIntPrime(bit), n};
    }

    public BigInteger encrypt(String line, BigInteger[] publicKey) { // message in power of (publicKey) mod(Modulus)

        String hex = hexutil.toHexString(line.getBytes(Charset.forName("utf-8")));
//        System.out.println(line.getBytes(Charset.forName("utf-8")).length);
//        System.out.println(hex.getBytes(Charset.forName("utf-8")).length);
        return new BigInteger(hex.getBytes()).modPow(publicKey[0], publicKey[1]);
    }

    public String decrypt(BigInteger encrypted, BigInteger privateKey, BigInteger[] publicKey) { // message in power of (privateKey) mod(Modulus)
//        System.out.println(convertFromUTF8(fromHexString(new String(encrypted.modPow(privateKey, publicKey[1]).toByteArray()))));
        return convertFromUTF8(
                new String(fromHexString(
                                new String(encrypted.modPow(privateKey, publicKey[1]).toByteArray())
                        )));
    }

    public BigInteger getBigIntPrime(int bit) {
        return BigInteger.probablePrime(bit, new Random());
    }

    public BigInteger getPrivateKey(BigInteger e, BigInteger phi) { // e⋅d=1modϕ(n) ( Extended Euclidean Algorithm )

        ArrayList<PrivateKeyEquation> equation = new ArrayList<PrivateKeyEquation>();

        equation.add(new PrivateKeyEquation(BigInteger.ONE, BigInteger.ZERO, phi, BigInteger.ZERO));
        equation.add(new PrivateKeyEquation(BigInteger.ZERO, BigInteger.ONE, e, phi.divide(e)));
        BigInteger d = e, result;
        int cnt = 1;

        while (!d.equals(BigInteger.ONE)) {
            PrivateKeyEquation equationTest = new PrivateKeyEquation(d, d, d, d);

            equationTest.a = (equation.get(cnt - 1).a.subtract(equation.get(cnt).a.multiply(equation.get(cnt).k)));
            equationTest.b = (equation.get(cnt - 1).b.subtract(equation.get(cnt).b.multiply(equation.get(cnt).k)));
            equationTest.d = (equation.get(cnt - 1).d.subtract(equation.get(cnt).d.multiply(equation.get(cnt).k)));
            equationTest.k = (equation.get(cnt).d.divide(equationTest.d));

            equation.add(equationTest);
            cnt++;
            d = equation.get(cnt).d;
        }
        return (((result = equation.get(equation.size() - 1).b).compareTo(BigInteger.ONE) == -1) ? result.add(phi) : result);
    }

    class PrivateKeyEquation {

        BigInteger a, b, d, k;

        public PrivateKeyEquation(BigInteger a, BigInteger b, BigInteger d, BigInteger k) {
            this.a = a;
            this.b = b;
            this.d = d;
            this.k = k;
        }
    }
}

class StringHexUtil {

    public String toHexString(byte[] input) {
        return new String(toHexCharArray(input));
    }

    public char[] toHexCharArray(byte[] input) {
        int m = input.length;
        int n = 2 * m;
        int l = 0;
        char[] output = new char[n];
        for (int k = 0; k < m; k++) {
            byte v = input[k];
            int i = (v >> 4) & 0xf;
            output[l++] = (char) (i >= 10 ? ('a' + i - 10) : ('0' + i));
            i = v & 0xf;
            output[l++] = (char) (i >= 10 ? ('a' + i - 10) : ('0' + i));
        }

        return output;
    }

    public byte[] fromHexString(String input) {
        int n = input.length() / 2;
        byte[] output = new byte[n];
        int l = 0;
        for (int k = 0; k < n; k++) {
            char c = input.charAt(l++);
            byte b = (byte) ((c >= 'a' ? (c - 'a' + 10) : (c - '0')) << 4);
            c = input.charAt(l++);
            b |= (byte) (c >= 'a' ? (c - 'a' + 10) : (c - '0'));
            output[k] = b;
        }
        return output;
    }

    public byte[] fromHexCharArray(char[] input) {
        return fromHexString(new String(input));
    }
}
