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
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.bouncycastle.util.encoders.Hex;

public class Cliente {
	
	
	BufferedReader in, consoleIn;
	
	PrintWriter out;
	
	Socket client;
	
	KeyPair keys;
	
	private SecretKeySpec symmetricKey;
		
	NovasoftCertificate certFact;
	
	String[] algs = {"AES", "HmacSHA256"};
	
	int id;
	
	String linea;
	
	//TODO CAMBIO DE CODIGO  ---
	BufferedWriter writer;
	
	//TODO CAMBIO DE CODIGO ---
	public Cliente(String hostName, int portNumber, int id){
		
		KeyPairGenerator generator;
		try{
			client = new Socket(hostName, portNumber);
			out = new PrintWriter(client.getOutputStream(), true);
			in = new BufferedReader(new InputStreamReader(client.getInputStream()));
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);
			keys = generator.generateKeyPair();
			this.id = id;
			consoleIn = new BufferedReader(new InputStreamReader(System.in));
			certFact = new NovasoftCertificate();
		}
		catch(Exception e){
			System.out.println("Somethin went wrong:\n" + e.getMessage());
			e.printStackTrace();
		}
	}
	
	//TODO CAMBIO DE CODIGO ---
	public void getReady(String linea, BufferedWriter writer){
		
		this.writer = writer;
		this.linea = id + ";" + linea;
	}
	
	//TODO CAMBIO DE CODIGO ---
	
	String readServerAns(String serverAns) throws IOException{
		serverAns = in.readLine();
		return serverAns;
	}
	
	void sendCertificate(){
		
		//TODO IMPORTANTE
		String certificate = "hello monitor, calificame suave please :)";
		try {
			byte[] byteCertificate = certFact.generateIntermediateCert(keys.getPublic(), keys.getPrivate(), certFact.generateInitialCert()).getEncoded();
			certificate = getByteArrayHexaString(byteCertificate);
			out.println(certificate);
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	void decodeSimetricKey(String simetricEncodedKey, String certificate){
		
		try {
			Cipher sherlock = Cipher.getInstance("RSA");
			sherlock.init(Cipher.DECRYPT_MODE, keys.getPrivate());
			
			
			byte[] clearBts = sherlock.doFinal(Hex.decode(simetricEncodedKey));
			symmetricKey = new SecretKeySpec(clearBts, 0, clearBts.length, algs[0]); algs[0] += "/ECB/PKCS5Padding";
			//String simetricKeyText = new String(clearBts);
			//System.out.println("Cliente - llave descifrada:" + simetricKeyText);
			
			sherlock.init(Cipher.ENCRYPT_MODE, certFact.getPublicKeyFromFile(certFact.certificateToFile(certificate)));
			byte[] cipheredKey = sherlock.doFinal(clearBts);
			//System.out.println("LS cifrada:");
			simetricEncodedKey = getByteArrayHexaString(cipheredKey);
			//System.out.println(simetricEncodedKey);
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
