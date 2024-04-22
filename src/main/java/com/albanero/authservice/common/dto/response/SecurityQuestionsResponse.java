package com.albanero.authservice.common.dto.response;

import lombok.Data;

@Data
public class SecurityQuestionsResponse {
	String question1;
	String question2;
	String question3;
	String question4;
	String question5;
	Boolean sqStatus;
}
