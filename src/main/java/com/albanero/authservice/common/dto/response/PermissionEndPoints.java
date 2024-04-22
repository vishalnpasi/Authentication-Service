package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.List;

@JsonInclude
@Data
public class PermissionEndPoints {
    String permissionName;
    String screenName;
    List<PlatformApiDetailsResponseDto> platformApiDetails;
}
