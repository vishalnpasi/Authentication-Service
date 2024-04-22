package com.albanero.authservice.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document(collection = "userProjectDefaults")
@Schema(description = "The persistent class for User Default Project.")
public class UserProjectDefaults {
	@Id
	private String id;
	@Indexed
	private String userId;
	private String orgId;
	private String projectId;
	private String projectName;
}
