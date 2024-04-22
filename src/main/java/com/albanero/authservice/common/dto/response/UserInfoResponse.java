package com.albanero.authservice.common.dto.response;

import lombok.Data;

@Data
public class UserInfoResponse {
	String sub;
	String email;
	String picture;
	Boolean emailVerified;
}
