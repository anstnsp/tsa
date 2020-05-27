package com.finger.tsa.tsa.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


import com.finger.tsa.common.response.CommonResult;
import com.finger.tsa.common.response.ResponseService;
import com.finger.tsa.common.response.SingleResult;
import com.finger.tsa.tsa.dto.TSADto;
import com.finger.tsa.tsa.service.TSAService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class TSAController {

	private static final Logger logger = LoggerFactory.getLogger( TSAController.class );
	
	private final ResponseService responseService;
	private final TSAService tsaservice; 
	private final MessageSource messageSource; 

	/**
	 * @see 전자계약문서 시점확인 - 등록
	 * @param PDF파일을 Binary Strings으로 변환한 값 
	 * @return PDF파일에 TimeStampToken이 삽입된 Binary Strings
	 * @author 김문수
	 */
	@PostMapping("/v1/tsa/gettoken")
	public SingleResult<String> getFileIncludedToken(@RequestBody TSADto dto) throws Exception {
		
		logger.debug("#### START getFileIncludedToken ####");
		String result = tsaservice.getFileIncludedToken(dto);
		return responseService.getSingleResult(result);

	}
	
	/**
	 * @see 전자계약문서 시점확인 - 검증 
	 * @param PDF에 TimeStampToken이 포함된 파일을 Binary Strings으로 변환한 값 
	 * @return 검증확인값
	 * @author 김문수
	 */
	@PostMapping("/v1/tsa/verify")
	public CommonResult verifyPdfFile(@RequestBody TSADto dto) throws Exception {
		
		logger.debug("#### START verifyPdfFile ####");
		boolean result = tsaservice.verifyPdfFile(dto);
		if(result) return responseService.getSuccessResult();	
		else return responseService.getFailResult(Integer.valueOf(getMessage("unVerified.code")), getMessage("unVerified.msg"));

	}
	
    //code정보에 해당하는 메시지를 조회.
    private String getMessage(String code) {
        return getMessage(code, null);
    }
    //code정보, 추가 argument로 현재 locale에 맞는 메시지를 조회.
    private String getMessage(String code, Object[] args) {
        return messageSource.getMessage(code, args, LocaleContextHolder.getLocale());
    }
    
}
