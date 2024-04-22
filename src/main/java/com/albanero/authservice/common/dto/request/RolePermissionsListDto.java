package com.albanero.authservice.common.dto.request;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class RolePermissionsListDto {

    @NotEmpty
    @Valid
    private List<RolePermission> rolePermissions;

}
