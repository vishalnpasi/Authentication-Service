package com.albanero.authservice.common.dto.response;

import lombok.Data;

@Data
public class UpdatedDetailsDto {
    String updatedById;
    String updatedByUserName;
    Long updatedAt;
}
