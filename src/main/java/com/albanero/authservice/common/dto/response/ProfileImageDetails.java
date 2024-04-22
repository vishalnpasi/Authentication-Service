package com.albanero.authservice.common.dto.response;


import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class ProfileImageDetails {
	private String s3FilePath;
	private String fileContent;
	private String fileFormat;
}
