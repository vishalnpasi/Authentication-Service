package com.albanero.authservice.common.dto.request;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.constraints.NotNull;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class DetachPermissionRequest {
    @NotNull(message = "Permission title must not be null.")
    private String permissionTitle;
    @NotNull(message = "Module request must not be null.")
    private String module;
    @NotNull(message = "Sub module must not be null.")
    private String subModule;
    private String roleName;
    private PermissionsRequest modified;
}
