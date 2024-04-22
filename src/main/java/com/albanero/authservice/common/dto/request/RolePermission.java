package com.albanero.authservice.common.dto.request;

import com.albanero.authservice.model.Permissions;
import com.albanero.authservice.model.PlatformApiDetails;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class RolePermission {
    @Valid
    private Permissions permissionDetails;
    @NotBlank
    private String roleName;
    @NotEmpty
    @Valid
    private List<PlatformApiDetails> platformApiDetails;
    @NotBlank
    private String module;
    private String subModule;

}
