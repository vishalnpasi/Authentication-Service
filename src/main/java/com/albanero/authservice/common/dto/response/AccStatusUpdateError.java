package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@Schema(description = "AccStatusUpdateError DTO class for set response while error in updating user account status")
public class AccStatusUpdateError {
    private String userId;
    private String fullName;
    private String reason;

    public void setFullName(String firstName, String lastName) {
        this.fullName = firstName + " " + lastName;
    }
}
