package com.albanero.authservice.common.dto.response;

import lombok.Data;

import java.util.List;
@Data
public class UserDetails {
    private String fullName;
    private List<RoleResponse> role;
}
