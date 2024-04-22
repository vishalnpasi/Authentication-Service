package com.albanero.authservice.common.dto.request;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class DetachApiRequest {
    @NotBlank
    private String permissionTitle;
    @NotBlank
    private String module;
    @NotBlank
    private String subModule;
    @NotBlank
    private String apiRoute;
    @NotBlank
    private String apiMethod;
}
