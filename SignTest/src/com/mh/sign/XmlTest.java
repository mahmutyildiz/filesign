package com.mh.sign;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.util.Collections;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

public class XmlTest {
	private static Document sign(Document doc) throws InstantiationException, IllegalAccessException, ClassNotFoundException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyException, MarshalException, XMLSignatureException, FileNotFoundException,
			TransformerException, Exception, NoSuchProviderException {

		String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");

		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

		DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA256, null);
		Transform transform = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
		Reference reference = fac.newReference("", digestMethod, Collections.singletonList(transform), null, null);
		SignatureMethod signatureMethod = fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null);
		CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
		
		
		
		KeyStore ks = KeyStore.getInstance("pkcs12", "SunJSSE"); 
		ks.load(new FileInputStream("faturadeneme@mmshs.gov.tr.pfx"),"075239".toCharArray());
		
		String alias = ks.aliases().nextElement();
		Certificate cert = ks.getCertificate(alias);

		Key privateKey = ks.getKey(alias, "075239".toCharArray());

//		// Create the SignedInfo
		SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(reference));
//
//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//		kpg.initialize(2048);
//
//		KeyPair kp = kpg.generateKeyPair();
//
		KeyInfoFactory kif = fac.getKeyInfoFactory();
		KeyValue kv = kif.newKeyValue(cert.getPublicKey());
		
		// Create a KeyInfo and add the KeyValue to it
		KeyInfo ki = kif.newKeyInfo(Collections.singletonList(kv));
		DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());

		XMLSignature signature = fac.newXMLSignature(si, ki);
		signature.sign(dsc);

		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();

		// output the resulting document
		OutputStream os;

		os = new FileOutputStream("xmlOut.xml");

		trans.transform(new DOMSource(doc), new StreamResult(os));
		return doc;

	}

	public static void main(String[] args) throws Exception {
		File fXmlFile = new File("deneme.xml");
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(fXmlFile);

		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		Result output = new StreamResult(new File("deneme-out.xml"));
		Source input = new DOMSource(doc);

		transformer.transform(input, output);

		Document d2 = sign(doc);

		System.out.println(d2);
	}
}
