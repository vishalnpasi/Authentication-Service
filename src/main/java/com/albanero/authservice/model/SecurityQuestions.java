package com.albanero.authservice.model;

import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "securityQuestions")
public class SecurityQuestions {
	@Id
	private String id;
	private List<String> questions;
}
