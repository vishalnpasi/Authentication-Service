package com.albanero.authservice.common.dto.request;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.constraints.NotNull;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class DeleteSubModuleRequest {
    @NotNull(message = "Sub module name must not be null.")
    String subModuleName;
    @NotNull(message = "Module name must not be null.")
    String moduleName;
}
