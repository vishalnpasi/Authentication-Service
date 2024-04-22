package com.albanero.authservice.model;
import java.util.List;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "products")
public class Product {

	@Id
	private String id;
	private List<String> orgId;
	private String name;
	private Boolean type;
	private String importMap;
	private List<String> onProd;
	private List<String> onBeta;
	private Navigation navigation;
	
}
