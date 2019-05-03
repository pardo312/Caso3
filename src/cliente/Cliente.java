package cliente;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;



public class Cliente {
	
	
	Socket socket;
	
	KeyPair keys;
	
	 SecretKey symmetricKey;
		
	X509v3CertificateBuilder certFact;
	BufferedReader in, consoleIn;
	
	PrintWriter out;
	BufferedWriter writer;

	String linea;
	String[] algs;
	
	int id;
	public Cliente(String hostName, int portNumber,int id){
		
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
	
	String readServerAns(String serverAns) throws IOException{
		serverAns = in.readLine();
		System.out.println("Servidor: " + serverAns);
		return serverAns;
	}
	
	void printAlgorithmsSelectionMenu(){
		System.out.println("1. Configurar algoritmo simetrico");
		System.out.println("2. Configurar algoritmo asimetrico");
		System.out.println("3. Configurar HMAC");
		System.out.println("4. Enviar algoritmos ");
	}
	
	void menuSimetrico(){
		System.out.println("1. AES ");
		System.out.println("2. Blowfish");
	}
	
	void menuAsimetrico(){
		System.out.println("La unica opcion disponiblees RSA");
		System.out.println();
	}
	
	void menuHmac(){
		System.out.println("1. HmacSHA1");
		System.out.println("2. HmacSHA256");
		System.out.println("3. HmacSHA384");
		System.out.println("4. HmacSHA512");
	}
	
	void sendAlgorithms(String algoritmos){
		boolean fin = false;
		ArrayList<String> params = new ArrayList<String>();
		
		while(!fin){
			String selected;
			int number;
			printAlgorithmsSelectionMenu();
			
			try{
				selected = consoleIn.readLine();
				number = Integer.parseInt(selected);				
				switch(number){
				case 1:
					//Caso simetrico
					if(params.contains("1")){
						System.out.println("Ya escogio el algoritmo simetrico");
						System.out.println();
						break;
					}
					params.add(selected);
					menuSimetrico();
					
					selected = consoleIn.readLine();
					number = Integer.parseInt(selected);
					switch(number){
					case 1:
						
						algs[0] = "AES";
						break;
					case 2:
						
						algs[0] = "Blowfish";
						break;
					}
					break;
				case 2:
					//Caso asimetrico
					if(params.contains("2")){
						System.out.println("Ya escogio el algoritmo simetrico");
						break;
					}
					params.add(selected);
					menuAsimetrico();
					
					break;
				case 3:
					//Caso HMAC
					if(params.contains("3")){
						System.out.println("Ya escogio el algoritmo simetrico");
						break;
					}
					params.add(selected);
					menuHmac();
					
					selected = consoleIn.readLine();
					number = Integer.parseInt(selected);
					switch(number){
					case 1:
						
						algs[1] = "HmacSHA1";
						break;
					case 2:
						
						algs[1] = "HmacSHA256";						
						break;
					case 3:
						
						algs[1] = "HmacSHA384";
						break;
					case 4:
						
						algs[1] = "HmacSHA512";
						break;
					}
					break;
				case 4:
					if(!params.contains("1") || !params.contains("2") || !params.contains("3")){
						fin = true;
						throw new Exception("Debe configurar todos los algoritmos");
					}
					algoritmos+= algs[0]+":RSA:"+algs[1].toUpperCase();
					System.out.println(algoritmos);
					out.println(algoritmos);
					fin  = true;
					System.out.println("Mensaje enviado");
					break;
				}
			} catch(Exception e){
				e.printStackTrace();
			}
		}
	}
	
	String sendCertificate(){
		
	
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

	  public void getReady(String linea, BufferedWriter writer)
	  {
	    this.writer = writer;
	    this.linea = (this.id + ";" + linea);
	  }
	
	
	public void executeProtocol() throws Exception{
		String serverAns = "";
		String clientAns;
		
		System.out.println("------Protocolo comenzado------(Responder en orden)");
		System.out.println("CLIENTE: HOLA");
		out.println("HOLA");
		
		try {
			serverAns = readServerAns(serverAns);
			
			if(!serverAns.equals("OK")) throw new Exception("El mensaje de respuesta ha sido:  " + serverAns);
			
			clientAns = "ALGORITMOS:";
			sendAlgorithms(clientAns);
			
			serverAns = readServerAns(serverAns);
			if(!serverAns.equals("OK")){
				throw new Exception("El mensaje de respuesta ha sido:  " + serverAns);
			}
			System.out.println("Cliente: Enviando certificado...");
			System.out.println("Certificado enviado: \n" + sendCertificate());
			serverAns = readServerAns(serverAns);
	
			
			String certificate = serverAns;
			certificateToFile(DatatypeConverter.parseHexBinary(certificate));
			FileInputStream fin = new FileInputStream("./data/cert.pem");
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate1 = (X509Certificate)f.generateCertificate(fin);
			PublicKey ks=certificate1.getPublicKey();
			
			Cipher c=Cipher.getInstance("RSA");
			c.init(Cipher.ENCRYPT_MODE, ks);
		
			String s=DatatypeConverter.printHexBinary(c.doFinal(symmetricKey.getEncoded()));
		System.out.println("Llave simetrica: ");
		imprimir(symmetricKey.getEncoded());
			out.println(s);
			
			serverAns = readServerAns(serverAns);
			
			Cipher c3=Cipher.getInstance("RSA");
			c3.init(Cipher.DECRYPT_MODE, keys.getPrivate());
			byte[] ans1=c3.doFinal(DatatypeConverter.parseHexBinary(serverAns));
			System.out.println("Llave simetrica recibida: ");
			imprimir(ans1);
			out.println("OK");
			
			Cipher c1=Cipher.getInstance(algs[0]);
			c1.init(Cipher.ENCRYPT_MODE, symmetricKey);
			String datos="15;41 24.2028,2 10.4418 ";
			String s1=DatatypeConverter.printHexBinary(c1.doFinal(datos.getBytes()));
			out.println(s1);
			byte[] bytes = datos.getBytes();
			HMac mac;
			if(algs[1].equals("HmacSHA1")){
				mac= new HMac(new SHA1Digest());
			}else if(algs[1].equals("HmacSHA256")){
				mac= new HMac(new SHA256Digest());
			}else if(algs[1].equals("HmacSHA384")){
				mac= new HMac(new SHA384Digest());
			}else{
				mac= new HMac(new SHA512Digest());
			}
			mac.init(new KeyParameter(symmetricKey.getEncoded()));
			
			  byte[] result = new byte[mac.getMacSize()];
		        

		        mac.update(bytes,0,bytes.length);
		   mac.doFinal(result, 0);
			System.out.println("Hash creado: ");
			imprimir(result);
			out.println(DatatypeConverter.printHexBinary(result));
			//Envia la llave simetrica de vuelta
		
			serverAns = readServerAns(serverAns);
			Cipher c2= Cipher.getInstance("RSA");
			c2.init(Cipher.DECRYPT_MODE, ks);
		byte[] ans=c2.doFinal(DatatypeConverter.parseHexBinary(serverAns));
		System.out.println("Hash recibido: ");
		imprimir(ans);
			
			
		} catch (IOException e) {
			e.printStackTrace();
		}catch(Exception e){
			System.out.println(e.getMessage());
		}
	}
	
	public static void imprimir(byte[] contenido){
		int i=0;
		for(;i<contenido.length-1;i++){
			System.out.print(contenido[i]+" ");
		}
		System.out.println(contenido[i]+" ");
	}
	public static void main(String[] args) {
		
		Cliente c = new Cliente("localhost", 8082,8);
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		try {
			c.executeProtocol();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
