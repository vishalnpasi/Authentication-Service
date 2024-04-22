package com.albanero.authservice.common.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Data;

import java.util.List;

@Data
@Schema(description = "Members Details Request DTO class for adding multiple org member API Calls")
public class MembersDetailsRequest {
    @Schema(description = "Email Ids of org member")
    List<String> emailIds;
    @Schema(description = "Role of org member")
    String role;
}
