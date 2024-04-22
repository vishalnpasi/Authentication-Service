package com.albanero.authservice.common.dto.request;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PermissionsRequest {
    String screen;
    String description;
    String permissionTitle;
    String subModule;
    String module;
}
