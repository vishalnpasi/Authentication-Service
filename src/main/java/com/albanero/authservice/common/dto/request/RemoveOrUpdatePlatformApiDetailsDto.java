package com.albanero.authservice.common.dto.request;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.constraints.NotNull;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class RemoveOrUpdatePlatformApiDetailsDto {
    @NotNull(message = "Api route must not be null.")
    private String apiRoute;
    @NotNull(message = "Api method must not be null.")
    private String apiMethod;
    PlatformApiDetailsDto modified;
}
