package com.finger.tsa.tsa.service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.finger.tsa.tsa.dto.TSADto;
import com.finger.tsa.util.TSATokenMaker;
import com.finger.tsa.util.Util;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TSAService {
	
	private static final Logger logger = LoggerFactory.getLogger(TSAService.class);
	
	public String getFileIncludedToken(TSADto dto) throws NoSuchAlgorithmException, IllegalArgumentException, OperatorCreationException, TSPException, IOException, InvalidKeySpecException, NullPointerException, CertificateException {

		String StringFromPdf = dto.getStrFromFile();

		//1.최초 요청으로 받은 PDF문서(Binary Strings)값의 해쉬 생성
		String hashedStringFromPdf = Util.getHashFromString(StringFromPdf);
		logger.debug("해쉬길이1:"+hashedStringFromPdf.length());
		logger.debug("pdf해시값:"+hashedStringFromPdf);
		//1-1.TST만들때 필요한 난수생성 
		BigInteger nonce = new BigInteger(32, new Random(System.currentTimeMillis()));
		
		//토큰생성기 초기화
		TSATokenMaker tsaTokenMaker = new TSATokenMaker();
		
		//인증서 설정
		tsaTokenMaker.setCert(tsaTokenMaker.getPublicKey("C:\\Users\\anstn\\Downloads\\tsa_cert.der"));
		tsaTokenMaker.setPrivateKey(tsaTokenMaker.getPrivateKey("C:\\Users\\anstn\\Downloads\\tsa_cert.key"));
		
		//2.TST(TimeStampToken)를 생성 후 토큰생성시간 리턴받음(timeGenToken)
		String timeGenToken = tsaTokenMaker.makeTimeStampToken(hashedStringFromPdf, nonce);
		logger.debug("토큰생성시간:"+timeGenToken);
		
	    byte[] buff = StringFromPdf.getBytes();  //Base64로 인코딩된 바이너리 스트링을 Base64로 디코딩 한 후 String으로 캐스팅한다. 
	    String toStr = new String(buff);
	    byte[] b64dec = Util.base64Dec(toStr); 

		//3.최초 받은 PDF문서에 토큰 삽입. 
		//("", 서명자로추가할이름, 지역, 원인?) 
	    ByteArrayOutputStream baos = tsaTokenMaker.setTimeStampTokenFromBinaryString(b64dec,"서명이름", "위치", "이유");
		byte[] bytedFile = baos.toByteArray();
		
		//토큰이 삽입된 pdf파일 
		String binaryPdfFileAddedToken = new String(Util.base64Enc(bytedFile));
		
		
	    //4.토큰이 삽입된 바이너리에 해쉬 생성. 
		String hashedStringFromPdfAddedToken = Util.getHashFromString(binaryPdfFileAddedToken);
		logger.debug("해쉬길이2:"+hashedStringFromPdfAddedToken.length());
		logger.debug("토큰삽입되바이너리해시값:"+hashedStringFromPdfAddedToken);
		//5.블록체인에 저장. (PdfHash: 원본pdf해쉬, PdfTokenHash: 토큰삽입된pdf해쉬, Tst: 타임스탬프토큰, IssuerDate: 토큰만들때 시점(yyyymmddhhmmss) , DocuSeq : 문서일련번호)
		//TODOS.... 5 
		
		//6.블록체인에 저장이 됐으면 결과(토큰이삽입된pdf 문자열) 리턴.
		return binaryPdfFileAddedToken;
	}

	
	public boolean verifyPdfFile(TSADto dto) throws NoSuchAlgorithmException {
		//받은 전자문서값.
		String binaryPdfFileAddedToken = dto.getStrFromFile();
		//1.받은 문서값의 해쉬 만듬.aaa
		String hashedStringFromPdfAddedToken = Util.getHashFromString(binaryPdfFileAddedToken); //NoSuchAlgorithmException
		
		//2.블록체인 내에 존재유무 확인 
		//hashedStringFromPdfAddedToken 를 블록체인에 전달(쿼리) 
		boolean isExists = true; 
		
		//3.2번에 따라 존재하면 검증됐다고 알리고 존재안하면 검증안됐다고 알리고. 
		return isExists; 
	}
	

	
}
