package cliente;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;



public class NovasoftCertificate{

	KeyPair keyPair;
	
	public SecureRandom getSr(){
		
			SecureRandom secureRandomGenerator;
			SecureRandom sr = null;
			try {
				secureRandomGenerator = SecureRandom.getInstance("SHA1PRNG");
			    // Get 128 random bytes
			    byte[] randomBytes = new byte[128];
			    secureRandomGenerator.nextBytes(randomBytes);
			 
			    // Create two secure number generators with the same seed
			    int seedByteCount = 5;
			    byte[] seed = secureRandomGenerator.generateSeed(seedByteCount);

			    sr = SecureRandom.getInstance("SHA1PRNG");
			    sr.setSeed(seed);
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			return sr;

	}
	@SuppressWarnings("deprecation")
	public X509Certificate generateInitialCert(){
		
		X509Certificate cert = null;
		
		Date startDate = new Date(System.currentTimeMillis() - 50000);// time from which certificate is valid
		Date expiryDate = new Date(System.currentTimeMillis() + 50000);// time after which certificate is not valid
		BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());     // serial number for certificate
		try {
			keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
			X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
			X500Principal dnName = new X500Principal("CN=Test CA Certificate");
			certGen.setSerialNumber(serialNumber);
			certGen.setIssuerDN(dnName);
			certGen.setNotBefore(startDate);
			certGen.setNotAfter(expiryDate);
			certGen.setSubjectDN(dnName);                       // note: same as issuer
			certGen.setPublicKey(keyPair.getPublic());
			certGen.setSignatureAlgorithm("SHA256WithRSA");
			cert = certGen.generate(keyPair.getPrivate(), "BC");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cert;
	}
	
	@SuppressWarnings("deprecation")
	public X509Certificate generateIntermediateCert(PublicKey intKey, PrivateKey caKey, X509Certificate caCert)
		    throws Exception
		{
		    X509V3CertificateGenerator  certGen = new X509V3CertificateGenerator();

		    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		    certGen.setIssuerDN(PrincipalUtil.getSubjectX509Principal(caCert));
		    certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
		    certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
		    certGen.setSubjectDN(new X509Principal("CN=Test Intermediate Certificate"));
		    certGen.setPublicKey(intKey);
		    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		    certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
		    certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(intKey.getEncoded()));
		    certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
		    certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));

		    return certGen.generate(caKey, "BC");
	}
	
	public String printByteArrayHexa(byte[] byteArray) {
		String out = "";
		for (int i = 0; i < byteArray.length; i++) {
			if ((byteArray[i] & 0xff) <= 0xf) {
				out += "0";
			}
			out += Integer.toHexString(byteArray[i] & 0xff).toUpperCase();
		}

		return out;
	}
	
	public File certificateToFile(String hexaCertificate){
		File pemFile = new File("./data/cert.pem");
		byte[] bts = Hex.decode(hexaCertificate);
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
	

	public static void main(String[] args) {
		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		NovasoftCertificate fact = new NovasoftCertificate();
		KeyPairGenerator generator;
		try {
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(1024);
			KeyPair keyPair = generator.generateKeyPair();
			X509Certificate v3cert = fact.generateIntermediateCert(keyPair.getPublic(), keyPair.getPrivate(), fact.generateInitialCert());
			byte[] certBytes = v3cert.getEncoded();
			String cert = fact.printByteArrayHexa(certBytes);
			System.out.println(fact.getPublicKeyFromFile(fact.certificateToFile(cert)));
			System.out.println(fact.keyPair.getPublic());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
}
