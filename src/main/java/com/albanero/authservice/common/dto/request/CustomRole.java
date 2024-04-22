package com.albanero.authservice.common.dto.request;

import com.albanero.authservice.common.dto.response.ModuleNameDto;
import com.albanero.authservice.model.RoleType;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CustomRole {
    @NotBlank
    String roleName;
    @NotEmpty
    List<String> permissionIdList;
    @Valid
    RoleType roleType;
    @NotBlank
    String description;
    @NotEmpty
    List<ModuleNameDto> permissionTree;
}
