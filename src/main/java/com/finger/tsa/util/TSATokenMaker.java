package com.finger.tsa.util;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TSATokenMaker implements SignatureInterface {
	private static final Logger logger = LoggerFactory.getLogger(TSATokenMaker.class);
	private PrivateKey privateKey;
	private X509Certificate cert;

	private PDSignature signature;
	private byte[] token;

	
	
	

	/**
	 * File을 받아 SHA-256 , BASE64 인코딩 값으로 만드는 함수
	 * 
	 * @param pdf File
	 * @return String ( SHA-256 base64 값 )
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public String sha256(File pdf) throws NoSuchAlgorithmException, IOException {
		BufferedReader br = null;
		logger.debug("sha256 START ");
		try {
			if (pdf == null) {
				throw new NullPointerException("null!! pdf File parameter !!");
			}
			logger.debug("HASH target PDF : {}", pdf.getAbsolutePath());
			MessageDigest hashSum = MessageDigest.getInstance("SHA-256");

			String sCurrentLine;
			br = new BufferedReader(new FileReader(pdf));
			while ((sCurrentLine = br.readLine()) != null) {
				byte[] data = sCurrentLine.getBytes("UTF8");
				hashSum.update(data);
			}
			return Base64.encodeBase64String(hashSum.digest());
		} catch (IOException e) {
			logger.error("sha256 Failed check File:{}", e.getMessage());
			throw e;
		} finally {
			try {
				if (br != null) {
					br.close();
				}
			} catch (IOException ex) {
				logger.error("BuffeReder Close Failed check system and jdk :{} ", ex.getMessage());
				throw ex;
			}
		}
	}

	/**
	 * 파라미터로 받은 경로로 개인키파일을 읽어 개인키 obj형태로 만드는 함수
	 * 
	 * @param path 개인키 인증서 경로
	 * @return PrivateKey
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws Exception
	 */
	public PrivateKey getPrivateKey(String path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NullPointerException {
		logger.debug("getPrivateKey START !!");
		try {
			logger.debug("path : {}", path);
			if (path == null || path.isEmpty()) {
				throw new NullPointerException("null or empty!! check parameter !!");
			}

			byte[] keyBytes = Files.readAllBytes(Paths.get(path));
			logger.debug("getPrivateKey keyBytes : {} ", keyBytes.length);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		} catch (IOException e) {
			logger.error("privatekey File read Failed \ncheck permission and path !! :  {}", e.getMessage());
			throw e;
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			logger.error("privatekey File read Failed \nJCE provider check !! :  {}", e.getMessage());
			throw e;
		}

	}

	/**
	 * 파라미터로 받은 경로로 공개키 파일을 읽어 공개키 키 obj형태로 만드는 함수
	 * 
	 * @param path 공개키 인증서 경로
	 * @return X509Certificate
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws CertificateException
	 */
	public X509Certificate getPublicKey(String path) throws CertificateException, IOException, NullPointerException {
		logger.debug("getPublicKey START !!");
		FileInputStream is = null;
		try {
			logger.debug("path : {}", path);
			if (path == null || path.isEmpty()) {
				throw new NullPointerException("null or empty!! check parameter !!");
			}
			is = new FileInputStream(new File(path));
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(is);
		} catch (IOException e) {
			logger.error("publicKey File read Failed \ncheck permission and path !! :  {}", e.getMessage());
			throw e;
		} catch (CertificateException e) {
			logger.error("{} is not Certificate check File!! :  {}", path, e.getMessage());
			throw e;
		} finally {
			try {
				is.close();
			} catch (IOException e) {
				logger.error("FileInputStream Close Failed check system and jdk :{} ", e.getMessage());
				throw e;
			}
		}

	}
	/**
	 * PDF에 TimeStampToken을 추가하는 함수
	 * 
	 * @param binaryString binaryString으로 변환한 pdf파일 
	 * @param signatureName 서명자로 추가할 이름
	 * @param Location      지역 필드
	 * @param reason        원인 필드
	 * @throws InvalidPasswordException
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	
	public ByteArrayOutputStream setTimeStampTokenFromBinaryString(byte[] binaryString, String signatureName,
			String Location, String reason) throws InvalidPasswordException, FileNotFoundException, IOException {
		logger.debug("setTimeStampTokenFromBinaryString START !! ");
		PDDocument doc = null;
		ByteArrayOutputStream ops = null;
		try {
			logger.debug("binary String = {}", binaryString);
			doc = PDDocument.load(binaryString);
			PDSignature signature = new PDSignature();
			signature.setSubFilter(COSName.getPDFName("ETSI.RFC3161")); //사용될 서명이 뭔지 적어줌 
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signature.setName(signatureName);
			signature.setLocation(Location);
			signature.setReason(reason);
			signature.setSignDate(Calendar.getInstance());
			doc.addSignature(signature, this);
			
			ops = new ByteArrayOutputStream();
			doc.saveIncremental(ops);
			doc.close();
			return ops;
		} catch (IOException e) {
			logger.error("setTimeStampTokenFromBinaryString Failed check path :{}", e.getMessage());
			throw e;
		} finally {
			try {
				doc.close();
				ops.close();
			} catch (Exception e) {
				logger.error("resource Close failed check FileOpen or System :{}", e.getMessage());
				throw e;
			}
		}
	}
	
	/**
	 * PDF에 TimeStampToken을 추가하는 함수
	 * 
	 * @param originPDFPath 서명할 대상 PDF
	 * @param outputPDFPath 서명후 생성할 PDF
	 * @param signatureName 서명자로 추가할 이름
	 * @param Location      지역 필드
	 * @param reason        원인 필드
	 * @throws InvalidPasswordException
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public void setTimeStampTokenInPdf(String originPDFPath, String outputPDFPath, String signatureName,
			String Location, String reason) throws InvalidPasswordException, FileNotFoundException, IOException {
		logger.debug("setTimeStampTokenInPdf START !! ");
		PDDocument doc = null;
		OutputStream ops = null;
		try {

			logger.debug(" PDF  = {}", originPDFPath);
			logger.debug(" PDF_OUT  = {}", outputPDFPath);
			doc = PDDocument.load(new FileInputStream(new File(originPDFPath)));
			PDSignature signature = new PDSignature();
			signature.setSubFilter(COSName.getPDFName("ETSI.RFC3161"));
			signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
			signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
			signature.setName(signatureName);
			signature.setLocation(Location);
			signature.setReason(reason);
			signature.setSignDate(Calendar.getInstance());
			doc.addSignature(signature, this);
			ops = new FileOutputStream(outputPDFPath);
			doc.saveIncremental(ops);
			doc.close();
		} catch (IOException e) {
			logger.error("setTimeStampTokenInPdf Failed check path :{}", e.getMessage());
			throw e;
		} finally {
			try {
				doc.close();
				ops.close();
			} catch (Exception e) {
				logger.error("resource Close failed check FileOpen or System :{}", e.getMessage());
				throw e;
			}
		}
	}

	/**
	 * TimeStampToken 생성
	 * 
	 * @param pdfHashB64Str PDF를 SHA-256하여 BSE64로 생성한 값
	 * @param nonce         랜덤값
	 * @return 토큰생성시간 
	 * @return TimeStampToken byte[]
	 * @throws TSPException
	 * @throws CertificateEncodingException
	 * @throws IllegalArgumentException
	 * @throws OperatorCreationException
	 * @throws IOException
	 */
	public String makeTimeStampToken(String pdfHashB64Str, BigInteger nonce) throws TSPException,
			CertificateEncodingException, IllegalArgumentException, OperatorCreationException, IOException {
		try {
			logger.debug("makeTimeStampToken START !! ");
			TimeStampRequestGenerator requestGen = new TimeStampRequestGenerator();
			requestGen.setCertReq(true);
			TimeStampRequest request = requestGen.generate(TSPAlgorithms.SHA256, Base64.decodeBase64(pdfHashB64Str),
					nonce);

			TimeStampTokenGenerator tstg;
			SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
		
			tstg = new TimeStampTokenGenerator(
					new JcaSimpleSignerInfoGeneratorBuilder().build("SHA256withRSA", privateKey, cert),
					new JcaDigestCalculatorProviderBuilder().build().get(
							new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)),
					new ASN1ObjectIdentifier("1.2"));

			TimeStampToken token;
			Date TokenGenTime = new Date();
			token = tstg.generate(request, BigInteger.ONE, TokenGenTime);
			
			this.token = token.getEncoded();
			
			return dateFormat.format(TokenGenTime);
		} catch (TSPException | CertificateEncodingException | IllegalArgumentException | OperatorCreationException e) {
			logger.error("makeTimeStampToken Failed :{}", e.getMessage());
			throw e;
		}

	}
	/**
	 *  TimeStampToken 객체로 변경해주는 함수
	 * @param timeStampToken
	 * @return TimeStampToken
	 * @throws CMSException
	 * @throws TSPException
	 * @throws IOException
	 */
	public TimeStampToken byteToTimeStamp(byte[] timeStampToken) throws CMSException, TSPException, IOException {
		logger.debug("byteToTimeStamp START !!");
		try {
			CMSSignedData signedToken = new CMSSignedData(timeStampToken);
			return new TimeStampToken(signedToken);
		} catch (CMSException |TSPException | IOException e) {
			logger.error("byteToTimeStamp failed check timeStampToken: {}", e.getMessage());
			throw e;
		} 

	}
	/**
	 * TimeStampToken 검증 함수
	 * @param timeStampToken
	 * @return
	 */
	public boolean verifyTimeStampToken(byte[] timeStampToken) {
		logger.debug("verifyTimeStampToken START !!");
		try {
			CMSSignedData signedToken = new CMSSignedData(timeStampToken);
			TimeStampToken ttoken = new TimeStampToken(signedToken);
			ttoken.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.build(cert));
			return true;
		} catch (TSPException | IOException | CMSException | OperatorCreationException e) {
			logger.error("verifyToken failed {} : {}", e.getClass().getName(), e.getMessage());
			return false;
		}
	}
	/**
	 * 서명 함수
	 */
	@Override
	public byte[] sign(InputStream content) throws IOException {
		return this.token;
	}

	// TEST
	public static void main(String[] args) {
		try {
			// TEST START
			logger.debug("TEST START !!");

			// JCE 초기화
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			// 토큰생성기 초기화
			TSATokenMaker ttmk = new TSATokenMaker();

			// 인증서 설정
			ttmk.setCert(ttmk.getPublicKey("C:\\workspace\\f-chain_TSA\\tsa\\cert\\tsa_cert.der"));
			ttmk.setPrivateKey(ttmk.getPrivateKey("C:\\workspace\\f-chain_TSA\\tsa\\cert\\tsa_cert.key"));

			// pdf Hash
			String hash = ttmk.sha256(new File("C:\\workspace\\f-chain_TSA\\tsa\\test\\test.pdf"));
			logger.debug("PDF HASH : {}", hash);

			// TimeStampToken 생성
			//byte[] token = ttmk.makeTimeStampToken(hash, BigInteger.valueOf(12345));

			// TimeStampToken 검증
			logger.debug("TimeStampToken verify : {}", ttmk.verifyTimeStampToken(ttmk.getToken()));

			// TimeStamp 정보출력
			TimeStampToken tst = ttmk.byteToTimeStamp(ttmk.getToken());
			TimeStampTokenInfo tinfo = tst.getTimeStampInfo();
			logger.debug("TimeStampToken genTime : {}", tinfo.getGenTime());
			logger.debug("TimeStampToken HASH : {}", Base64.encodeBase64String(tinfo.getMessageImprintDigest()));
			logger.debug("TimeStampToken Nonce : {}", tinfo.getNonce());
			logger.debug("TimeStampToken SerialNumber : {}", tinfo.getSerialNumber().toString());

			// TimeStampToken 적용 된 pdf 생성
			ttmk.setTimeStampTokenInPdf("C:\\workspace\\f-chain_TSA\\tsa\\test\\test.pdf",
					"C:\\workspace\\f-chain_TSA\\tsa\\test\\test_signed.pdf", "finger", "kr-ko", "계약서 서명");
			System.out.println("done");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
