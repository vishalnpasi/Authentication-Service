package com.albanero.authservice.common.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.ArrayList;


@Data
@Schema(description = "users id to approve multiple users")
public class UserAccountStatus {
    private ArrayList<String> userId;
    private Boolean isAccountApproved;
    private Boolean isAccountActivated;
    private Boolean isAccountUnblock;
}
