package com.finger.tsa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestContoller {

	private final Logger logger = LoggerFactory.getLogger(TestContoller.class);
	@GetMapping("/test")
	public String test() {
		 logger.debug("디버그당");
		 logger.error("에러당");
		return "test";
	}
}
