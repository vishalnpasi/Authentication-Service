package com.albanero.authservice.common.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "User Block Status DTO class")
public class UserBlockStatusDto {
    private String userid;
    private Boolean status;
}
