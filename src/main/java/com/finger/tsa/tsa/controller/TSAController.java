package com.finger.tsa.tsa.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
	
	/**
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
	 * @param PDF에 TimeStampToken이 포함된 파일을 Binary Strings으로 변환한 값 
	 * @return 검증확인값
	 * @author 김문수
	 */
	@PostMapping("/v1/tsa/verify")
	public CommonResult verifyPdfFile() {
		logger.debug("#### START getTSAToken ####");
		try {
			return responseService.getSuccessResult();	
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null; 
	}
}
