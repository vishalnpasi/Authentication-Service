package com.albanero.authservice.model;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "secQuesStatus")
public class SecurityQuestionStatus {
	@Id
	private String id;
	@Indexed(unique = true)
	private String userId;
	private String question;
	private Boolean isUsingSQ;
	private String answer;
}
