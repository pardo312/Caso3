package cliente;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.management.ManagementFactory;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import org.bouncycastle.util.encoders.Hex;
import java.io.FileInputStream;
import java.io.Writer;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;


public class Cliente {
	
	
	BufferedReader in, consoleIn;
	
	PrintWriter out;
	
	Socket socket;
	
	KeyPair keys;
	
	SecretKey symmetricKey;
		
	X509v3CertificateBuilder certFact;
	
	
	String[] algs = {"AES", "HmacSHA256"};
	
	int id;
	
	String linea;
 
	BufferedWriter writer;
	
	//TODO CAMBIO DE CODIGO ---
	public Cliente(String hostName, int portNumber, int id){
		
		KeyPairGenerator generator;
		KeyGenerator g;
		try{
			g=KeyGenerator.getInstance("AES");
			symmetricKey=g.generateKey();
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);
			keys = generator.generateKeyPair();
			this.id=id;
			socket = new Socket(hostName, portNumber);
			out = new PrintWriter(socket.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			consoleIn = new BufferedReader(new InputStreamReader(System.in));
			Calendar start = Calendar.getInstance();
			Calendar expiry = Calendar.getInstance();
			expiry.add(Calendar.YEAR, 1);
			certFact = new X509v3CertificateBuilder(new X500Name("CN=l"), BigInteger.ONE, start.getTime(), expiry.getTime(),new X500Name("CN=l"),SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()));
			algs = new String[2];
		}
		catch(Exception e){
			System.out.println("Somethin went wrong:\n" + e.getMessage());
			e.printStackTrace();
		}
	}
	

	public void getReady(String linea, BufferedWriter writer){
		
		this.writer = writer;
		this.linea = id + ";" + linea;
	}
	

	String readServerAns(String serverAns) throws IOException{
		serverAns = in.readLine();
		System.out.println("Servidor: " + serverAns);
		return serverAns;
	}
	
	String sendCertificate(){
		
		//TODO IMPORTANTE
		String certificate = "";
		try {
			ContentSigner signer = new JcaContentSignerBuilder("SHA1WithRSA").setProvider(new BouncyCastleProvider()).build(keys.getPrivate());
			X509CertificateHolder holder = certFact.build(signer);
			java.security.cert.X509Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
			byte[] byteCertificate = cert.getEncoded();
			certificate = DatatypeConverter.printHexBinary(byteCertificate);
			out.println(certificate);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return certificate;
	}
	
	void decodeSimetricKey(String simetricEncodedKey, String certificate){
		
		try {
			Cipher c3 = Cipher.getInstance("RSA");
			c3.init(Cipher.DECRYPT_MODE, keys.getPrivate());
			
			
			byte[] clearBts = c3.doFinal(Hex.decode(simetricEncodedKey));
			symmetricKey = new SecretKeySpec(clearBts, 0, clearBts.length, algs[0]); algs[0] += "/ECB/PKCS5Padding";
			
			certificateToFile(DatatypeConverter.parseHexBinary(certificate));
			FileInputStream fin = new FileInputStream("./data/cert.pem");
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate1 = (X509Certificate)f.generateCertificate(fin);
			
					
			c3.init(Cipher.ENCRYPT_MODE,certificate1.getPublicKey());
			byte[] cipheredKey = c3.doFinal(clearBts);
			simetricEncodedKey = getByteArrayHexaString(cipheredKey);			
			out.println(simetricEncodedKey);
			
			
			
		} catch (Exception e) {
			out.println("ERROR");
			System.out.println(id + " " + e.getMessage());
			e.printStackTrace();
		}
	}
	
	void sendEncodedQuery(String queryCode){
		byte[] clearText = queryCode.getBytes();
		byte[] cipheredText, macMss;
		try {
			
			//Obtiene el hmac del Mensaje
			Mac mac = Mac.getInstance(algs[1]);
			mac.init(symmetricKey);
			macMss = mac.doFinal(queryCode.getBytes());
			
			//Encripta y envía el mensaje
			Cipher cipher = Cipher.getInstance(algs[0]);
			cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
			cipheredText = cipher.doFinal(clearText);
			
			queryCode = getByteArrayHexaString(cipheredText);
			//System.out.println(queryCode);
			out.println(queryCode);
			
			//Envía el hash del mensaje
			queryCode = getByteArrayHexaString(macMss);
			out.println(queryCode);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	private String getByteArrayHexaString(byte[] byteArray) {
		String out = "";
		for (int i = 0; i < byteArray.length; i++) {
			if ((byteArray[i] & 0xff) <= 0xf) {
				out += "0";
			}
			out += Integer.toHexString(byteArray[i] & 0xff).toUpperCase();
		}

		return out;
	}
	
	
	//TODO CAMBIO DE CODIGO ---
	public void executeProtocol() throws Exception{
		String serverAns = "OK";
		
		//System.out.println("CLIENTE: HOLA");
		out.println("HOLA");
		
		try {
			serverAns = readServerAns(serverAns);
			serverAns = "OK";
			//System.out.println();
			if(!serverAns.equals("OK")) throw new Exception("El mensaje de respuesta ha sido:  " + serverAns);
						
			//CAMBIO DE CODIGO --- ENVIA ALGORITMOS
			out.println("ALGORITMOS:AES:RSA:HMACSHA256");
			serverAns = readServerAns(serverAns);
			
			if(!serverAns.equals("OK")){
				throw new Exception("El mensaje de respuesta ha sido:  " + serverAns);
			}
			
			sendCertificate();
			serverAns = readServerAns(serverAns);
			
			//RECIBE CERTIFICADO DE SERVIDOR
			serverAns = readServerAns(serverAns);
			String certificate = serverAns;
			out.println("OK"); 
			
			// AQUÍ EMPIEZA FASE DE TIEMPO DE VERIFICACION
			double verTimeBegin = System.currentTimeMillis();
			serverAns = readServerAns(serverAns);	
			
			//Envia la llave simetrica de vuelta
			decodeSimetricKey(serverAns, certificate);
			serverAns = readServerAns(serverAns);
			//TODO CAMBIO DE CODIGO
			double timeRecorded = System.currentTimeMillis() - verTimeBegin;
			double cpuVer = getSystemCpuLoad();
			linea += (timeRecorded + ";");
			linea += (cpuVer + ";");
			//TODO FIN --- REGISTRA TIEMPO DE VERIFICACION
			
			Random r = new Random();
			int low = 1000;
			int high = 10000;
			int result = r.nextInt(high-low) + low;
			
			//TODO CAMBIO DE CODIGO ---
			double respTimeBegin = System.currentTimeMillis();
			sendEncodedQuery(String.valueOf(result));
			serverAns = readServerAns(serverAns);
			double respTimeRecorded = System.currentTimeMillis() - respTimeBegin;
			linea += (respTimeRecorded + ";");
			writer.write(linea + "\n");
			System.out.println(linea + timeRecorded);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public File certificateToFile(byte[] hexaCertificate){
		File pemFile = new File("./data/cert.pem");
		byte[] bts =hexaCertificate;
		try(Writer writer = new FileWriter("./data/cert.pem"); PemWriter pemWrt = new PemWriter(writer)){
			pemWrt.writeObject(new PemObject("CERTIFICATE",bts));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return pemFile;
	}
	
	public PublicKey getPublicKeyFromFile(File pemFile){
		CertificateFactory fact = null;
		PublicKey key = null;
		try {
			fact = CertificateFactory.getInstance("X.509");
			FileInputStream is = new FileInputStream (pemFile);
		    X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
		    key = cer.getPublicKey();
		} catch (Exception e) {
			e.printStackTrace();
		}

	    return key;
	}
	public double getSystemCpuLoad() throws Exception {
		MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		ObjectName name = ObjectName.getInstance("java.lang:type=OperatingSystem");
		AttributeList list = mbs.getAttributes(name, new String[]{ "SystemCpuLoad" });
		if (list.isEmpty()) return Double.NaN;
		Attribute att = (Attribute)list.get(0);
		Double value = (Double)att.getValue();
		// usually takes a couple of seconds before we get real values
		if (value == -1.0) return Double.NaN;
		// returns a percentage value with 1 decimal point precision
		return ((int)(value * 1000) / 10.0);
		
	}
	
	public static void main(String[] args) {
		try{
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			Cliente ivan = new Cliente("LocalHost", 8083, 8);
			ivan.executeProtocol();
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
}
