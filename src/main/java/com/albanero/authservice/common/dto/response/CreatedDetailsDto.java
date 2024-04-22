package com.albanero.authservice.common.dto.response;

import lombok.Data;

@Data
public class CreatedDetailsDto {
    String createdById;
    String createdByUserName;
    Long createdAt;
}
