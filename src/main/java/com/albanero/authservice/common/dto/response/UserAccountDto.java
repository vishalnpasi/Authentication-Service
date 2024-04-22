package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class UserAccountDto {
    Boolean mfaStatus;
    Boolean userAccess;
    Boolean validEmail;
    Boolean validUserName;
}
