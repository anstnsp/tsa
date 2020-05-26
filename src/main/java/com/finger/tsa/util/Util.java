package com.finger.tsa.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Util {

	private static final Logger logger = LoggerFactory.getLogger(Util.class);
	
	/**
	 * 파일을 바이너리 스트링으로 변경
	 *
	 * @param file
	 * @return String 
	 * @throws IOException 
	 */
	public static String fileToBinary(File file) throws IOException {
	    String out = new String();
	    FileInputStream fis = null;
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	 
	    try {
	        fis = new FileInputStream(file); //파일객체를 FileInputStream으로 생성.
	    } catch (FileNotFoundException e) {
	        logger.error("Exception position : FileUtil(FileNotFound) - fileToString(File file)");
	    }
	 
	    int len = 0;
	    byte[] buf = new byte[1024];
	    try {
	        while ((len = fis.read(buf)) != -1) { //FileInputStream을  ByteArrayOutputStream에 쓴다.
	            baos.write(buf, 0, len);
	        }
	 
	        byte[] fileArray = baos.toByteArray(); //ByteArrayOutputStream 를 ByteArray 로 캐스팅한다
	        out = new String(base64Enc(fileArray));  //캐스팅 된 ByteArray를 Base64 로 인코딩한 후 String 로 캐스팅한다.

	    } catch (IOException e) {
	        logger.error("Exception position : FileUtil(IOException) - fileToString(File file)");
	    } finally {
	    	if(fis != null) try { fis.close();} catch(IOException e) { 
	    		logger.error("Exception position : FileUtil(IOException) - fileToString(File file)"); 
	    		throw e;
	    	}
	    	if(baos != null) try { baos.close();} catch(IOException e) { 
	    		logger.error("Exception position : FileUtil(IOException) - fileToString(File file)"); 
	    		throw e;
	    	}
	    }
	 
	    return out;
	}
	
	/**
	 * 
	 * @param pdf파일을 바이너리스트링으로 변환한 값 
	 * @return pdf파일을 바이너리스트링을 SHA-256으로 해쉬한 후 Base64로 인코딩한 String값 .
	 * @throws NoSuchAlgorithmException
	 */
	public static String getHashFromString(String StringFromPdf) throws NoSuchAlgorithmException {
		//최초받은 바이너리스트링 값을 바이트배열로 바꿈. 
		byte[] byteArr = binaryStringToByteArray(StringFromPdf);
		
		MessageDigest hashSum = MessageDigest.getInstance("SHA-256");
		hashSum.update(byteArr);
		String hashedStringFromPdf = Base64.encodeBase64String(hashSum.digest()); //해쉬생성 후 베이스64스트링 인코딩 .
		return hashedStringFromPdf;
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IllegalArgumentException, OperatorCreationException, TSPException, IOException, InvalidKeySpecException, NullPointerException, CertificateException {
		System.out.println("시작함");
		//1.파일을 바이너리 스트링으로변경  (딴쪽에서 요청옴)
		File testFile = new File("C:\\Users\\anstn\\Downloads\\tsa_test_test.pdf");
		String toRes = fileToBinary(testFile);  //toRes는 바이너리스트링임. 
		
		System.out.println("##############:"+toRes);
		//요청으로 받은 바이너리스트링을 바이트배열로 바꿈. 
		byte[] ff = binaryStringToByteArray(toRes); 
	
	    byte[] buff = toRes.getBytes();  //Base64로 인코딩된 바이너리 스트링을 Base64로 디코딩 한 후 String으로 캐스팅한다. 
	    String toStr = new String(buff);
	    byte[] b64dec = base64Dec(toStr);
	    
		//toRes를 해쉬 (바이너리스트링을 해쉬) 
		MessageDigest hashSum = MessageDigest.getInstance("SHA-256");
		hashSum.update(ff); //해쉬값 업데이트 
		
		String hashedPdf = Base64.encodeBase64String(hashSum.digest()); //해쉬생성 후 베이스64스트링 인코딩 .
		//System.out.println(hashedPdf);
		// 토큰생성기 초기화
		TSATokenMaker ttmk = new TSATokenMaker();
		
		// 인증서 설정
		ttmk.setCert(ttmk.getPublicKey("C:\\Users\\anstn\\Downloads\\tsa_cert.der"));
		ttmk.setPrivateKey(ttmk.getPrivateKey("C:\\Users\\anstn\\Downloads\\tsa_cert.key"));
		
		// TimeStampToken 생성
		//byte[] token = ttmk.makeTimeStampToken(hashedPdf, BigInteger.valueOf(12345));

		// TimeStampToken 적용 된 pdf 생성
//		ttmk.setTimeStampTokenInPdf("C:\\workspace\\f-chain_TSA\\tsa\\test\\test.pdf",
//				"C:\\workspace\\f-chain_TSA\\tsa\\test\\test_signed.pdf", "finger", "kr-ko", "계약서 서명");
		
		ByteArrayOutputStream bii = ttmk.setTimeStampTokenFromBinaryString(b64dec,"finger","kr-ko","서명임");
		
		//System.out.println("bii:"+ bii);
		byte[] fileArray = bii.toByteArray();
		String aa = new String(base64Enc(fileArray));

		//toRes가 나한테옴. 
		binaryToFile(aa, "C:/Users/anstn/Downloads/","문수짱짱맨.pdf");
		System.out.println("끝");

	}

	/**
	 * 바이너리 스트링을 파일로 변환
	 *
	 * @param binaryFile
	 * @param filePath
	 * @param fileName 
	 * @return
	 * @throws IOException 
	 */
	public static File binaryToFile(String binaryFile, String filePath, String fileName) throws IOException {
		
	    if ((binaryFile == null || "".equals(binaryFile)) || (filePath == null || "".equals(filePath))
	            || (fileName == null || "".equals(fileName))) { return null; }
	 
	    FileOutputStream fos = null;
	 
	    File fileDir = new File(filePath);  //파일을 저장할 경로가 없으면 만들어 준다.
	    if (!fileDir.exists()) {
	        fileDir.mkdirs();
	    }
	 
	    File destFile = new File(filePath + fileName); //파일경로와 파일명을 합치고 파일 객체를 만든다.
	 
	    byte[] buff = binaryFile.getBytes();  //Base64로 인코딩된 바이너리 스트링을 Base64로 디코딩 한 후 String으로 캐스팅한다. 
	    String toStr = new String(buff);
	    byte[] b64dec = base64Dec(toStr);
	 
	    try {
	        fos = new FileOutputStream(destFile);  //26~32 : 바이너리 스트링을 생성한 파일객체에 써서 파일로 만든다. 
	        fos.write(b64dec);
	        fos.close();
	    } catch (IOException e) {
	        System.out.println("Exception position : FileUtil(IOException) - binaryToFile(String binaryFile, String filePath, String fileName)");
	    } finally {
	    	if(fos != null) try { fos.close();} catch(IOException e) { 
	    		logger.error("Exception position : FileUtil(IOException) - binaryToFile(String binaryFile, String filePath, String fileName)"); 
	    		throw e;
	    	}
	    }
	 
	    return destFile;
	}

	public static byte[] base64Enc(byte[] buffer) {
	    return Base64.encodeBase64(buffer);

	}

	public static byte[] base64Dec(String binaryString) {
		return Base64.decodeBase64(binaryString);

	}


    /**
     * 바이너리 스트링을 바이트배열로 변환
     * 
     * @param s
     * @return
     */
    public static byte[] binaryStringToByteArray(String s) {
        int count = s.length() / 8;
        byte[] b = new byte[count];
        for (int i = 1; i < count; ++i) {
            String t = s.substring((i - 1) * 8, i * 8);
            b[i - 1] = binaryStringToByte(t);
        }
        return b;
    }

    /**
     * 바이너리 스트링을 바이트로 변환
     * 
     * @param s
     * @return
     */
    public static byte binaryStringToByte(String s) {
        byte ret = 0, total = 0;
        for (int i = 0; i < 8; ++i) {
            ret = (s.charAt(7 - i) == '1') ? (byte) (1 << i) : 0;
            total = (byte) (ret | total);
        }
        return total;
    }

}
