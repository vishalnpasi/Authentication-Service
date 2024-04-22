package com.albanero.authservice.model;

import java.util.List;

import org.springframework.data.mongodb.core.mapping.Document;

import lombok.Data;

@Data
@Document(collection = "products")
public class Panel {
	private String name;
	private String icon;
	private String order;
	private String id;
	private List<Children> children;
}
