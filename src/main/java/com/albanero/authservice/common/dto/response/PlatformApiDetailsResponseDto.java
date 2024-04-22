package com.albanero.authservice.common.dto.response;


import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@JsonInclude
@Data
public class PlatformApiDetailsResponseDto {
    String endPoint;
    String method;
}
