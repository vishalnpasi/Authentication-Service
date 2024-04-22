package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@Schema(description = "AddMemberResponse DTO class for set response while Adding Member to the Project.")
public class AddMemberResponse {
    private String email;
    private String fullname;
    private String message;
    private Boolean success;
    private String role;
}
