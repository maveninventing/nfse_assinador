/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.commons.io.IOUtils;
import org.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * Assinador de lotes de XML'S para a NFSE Porto Alegre
 * @author Marison Souza - Maven Inventing
 * 
 */
public class AssinadorXML {

    private static final XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
    private static final ArrayList transformList = new ArrayList();

    static {
        try {
            TransformParameterSpec tps = null;
            Transform c2 = fac.newTransform(CanonicalizationMethod.INCLUSIVE, tps);
            transformList.add(c2);
        } catch (Exception ex) {
        }
    }

    public static void assinaXML(File xmlOriginal, File xmlAssinado, File certificadoA1, String senhaCertificado) throws Exception{
                
        File out = xmlAssinado;
        String key = certificadoA1.getAbsolutePath();
        String pass = senhaCertificado;
                
        String xml = IOUtils.toString(new FileInputStream(xmlOriginal));
        xml = normalize(xml);         
                
        Document doc = strToDoc(xml);
        doc.setXmlStandalone(true);
        doc.getDocumentElement().removeAttribute("xmlns:ns2");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(key), pass.toCharArray());

        KeyStore.PrivateKeyEntry pkEntry = null;
        Enumeration aliasesEnum = ks.aliases();
        PrivateKey privateKey = null;
        String aliasCertificado = "";
        if (aliasCertificado.isEmpty()) {
            while (aliasesEnum.hasMoreElements()) {
                aliasCertificado = (String) aliasesEnum.nextElement();
                if (ks.isKeyEntry(aliasCertificado)) {
                    pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(aliasCertificado, new KeyStore.PasswordProtection(
                            pass.toCharArray()));
                    privateKey = pkEntry.getPrivateKey();
                    break;
                }
            }
        } else {
            pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(aliasCertificado, new KeyStore.PasswordProtection(
                    pass.toCharArray()));
            privateKey = pkEntry.getPrivateKey();
        }

        X509Certificate cert = (X509Certificate) pkEntry.getCertificate();
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));


        assinar(doc, "InfRps", true, privateKey, ki);
        assinar(doc, "LoteRps", true, privateKey, ki);
        docToOut(doc,new FileOutputStream(out));
                
    }

    public static String geraXML(InfNfse objeto) {
        StringBuilder buff = new StringBuilder();
        buff.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
        objeto.geraXML(buff);
        return buff.toString();
    }

    /**
     * Assinatura do XML de Envio de Lote da NFS-e utilizando Certificado
     * Digital A1.
     */
    public static void assinar(Document doc, String tag, boolean includeSignatureID, PrivateKey privateKey, KeyInfo ki) throws Exception {

        Node element = doc.getElementsByTagName(tag).item(0);
        Element el = (Element) element;
        el.setIdAttribute("Id", includeSignatureID);
        String id = el.getAttribute("Id");
        
        Reference ref = fac.newReference("#" + id, fac.newDigestMethod(DigestMethod.SHA1, null), transformList, null, null);
        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null), fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));
        XMLSignature signature = fac.newXMLSignature(si, ki);
        DOMSignContext dsc = new DOMSignContext(privateKey, el.getParentNode());
        signature.sign(dsc);
    }

    public static String normalize(String str) {
        String xml = str;
        if ((xml != null) && (!"".equals(xml))) {
            xml = xml.replaceAll("\\r\\n", "");
            xml = xml.replaceAll("\\r", "");
            xml = xml.replaceAll("\\n", "");
            xml = xml.replaceAll("\\>\\s+\\<", "><");
            xml = xml.replaceAll("(\\s\\s)", "");
            xml = xml.replaceAll(" standalone=\"no\"", "");
        }
        return xml;
    }

    public static Document strToDoc(String xml) throws ParserConfigurationException, SAXException, IOException {
        xml = normalize(xml);
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document document = factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes()));
        return document;
    }

    public static String docToOut(Document doc,OutputStream os) throws Exception {        
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
        return os.toString();
    }
}
