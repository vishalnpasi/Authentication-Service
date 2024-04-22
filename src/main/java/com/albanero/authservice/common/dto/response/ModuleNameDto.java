package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ModuleNameDto {
    String id;
    String label;
    Boolean isSelected;
    Boolean indeterminate;
    String uniqueLabel;
    List<ModuleNameDto> sub;
}
