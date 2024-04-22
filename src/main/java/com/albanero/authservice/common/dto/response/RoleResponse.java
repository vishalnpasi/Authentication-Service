package com.albanero.authservice.common.dto.response;

import com.albanero.authservice.common.dto.ProjectOrgRoleId;
import com.albanero.authservice.model.Role;
import lombok.Data;

@Data
public class RoleResponse {
    private String roleId;
    private String projectOrgRoleId;
    private Boolean isDefault;
    private String role;

    public RoleResponse(Role role, ProjectOrgRoleId projectOrgRoleId) {
        this.roleId = role.getId();
        this.role = role.getRoleName();
        this.projectOrgRoleId = projectOrgRoleId.getProjectOrganizationRoleId();
        this.isDefault = projectOrgRoleId.getIsDefault();
    }
}
