package com.albanero.authservice.controller;


import com.albanero.authservice.common.dto.request.Auth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.albanero.authservice.common.dto.request.AuthRequest;
import com.albanero.authservice.common.dto.request.VaultDetails;
import com.albanero.authservice.common.util.RestUtil;

@RestController
public class TestController {

	private static final Logger LOGGER = LoggerFactory.getLogger(TestController.class);

	@GetMapping("/hellouser")
	public ResponseEntity<String> getUser() {
		LOGGER.error("HELLO USER!");
		return ResponseEntity.ok("hello");
	}

	@GetMapping("/getVaultToken")
	public String getAdmin() {
		AuthRequest authRequest = new AuthRequest();
		authRequest.setPassword("test");
		ResponseEntity<VaultDetails> vaultDetailsResponse = RestUtil
				.post("http://127.0.0.1:8200/v1/auth/userpass/login/arunima", null, authRequest, VaultDetails.class);
		if(vaultDetailsResponse != null){
			VaultDetails vaultDetails = vaultDetailsResponse.getBody();
			if(vaultDetails!= null){
				Auth vaultAuth = vaultDetails.getAuth();
				if(vaultAuth != null){
					return vaultAuth.getClientToken();
				}
			}
		}
		return "";
	}
}
