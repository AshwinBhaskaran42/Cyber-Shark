//import java.io.*;
import java.net.*;
import java.security.cert.*;
import java.security.KeyStore;
import javax.net.ssl.*;

public class SSLCertVerification {

    public static void main(String[] args) {

        String url = "https://www.amazon.in/"; 
        HttpsURLConnection connection = null;
        
        try {
            
            URL urlObj = new URL(url);
            connection = (HttpsURLConnection) urlObj.openConnection();
            connection.connect();

            
            Certificate[] certs = connection.getServerCertificates();

            
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null); 
            tmf.init(ks);
            X509Certificate[] chain = new X509Certificate[certs.length];
            for (int i = 0; i < certs.length; i++) {
                chain[i] = (X509Certificate) certs[i];
            }
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            SSLSocketFactory socketFactory = context.getSocketFactory();
            socketFactory.createSocket().close();

            
            X509Certificate cert = (X509Certificate) certs[0];
            String issuer = cert.getIssuerDN().getName();
            String[] parts = issuer.split(",");
            for (String part : parts) 
            {
                if (part.trim().startsWith("CN=")|| part.trim().startsWith("O=") ) //Common Name 
                {
                    String issuerName = part.trim().substring(2);
                    System.out.println("The SSL certificate for " + url + " is issued by " + issuerName + ".");
                    System.out.println("Issuer information:");
                    System.out.println(cert.getIssuerDN().getName());
                    System.out.println("Issued on: " + cert.getNotBefore());
                    System.out.println("Expires on: " + cert.getNotAfter());
                    break;
                }
                else
                {	
                	System.out.println("The SSL certificate for " + url + " is not issued by any Trustworthy Issuer. "); 	
                }
             }
            
        }
        catch (Exception e) {
        	System.out.println("The SSL certificate for " + url + " is not issued by any Trustworthy Issuer. "); 
            //e.printStackTrace();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}