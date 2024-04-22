package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.ArrayList;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AccountStatusUpdate {

    private ArrayList<String> approvedUserIds = new ArrayList<>();
    private ArrayList<String> activatedUserIds = new ArrayList<>();
    private ArrayList<String> deactivatedUserIds = new ArrayList<>();
    private ArrayList<String> unblockedUserIds = new ArrayList<>();
    private ArrayList<AccStatusUpdateError> errorUpdatingStatus = new ArrayList<>();

    public void setUserApprovedId(String userId) {
        this.approvedUserIds.add(userId);
    }

    public void setUserActivatedId(String userId) {
        this.activatedUserIds.add(userId);
    }

    public void setUserDeactivatedId(String userId) {
        this.deactivatedUserIds.add(userId);
    }

    public void setUserUnblockId(String userId) {
        this.unblockedUserIds.add(userId);
    }

    public void setUserAccStatusUpdateError(AccStatusUpdateError updateError) {
        this.errorUpdatingStatus.add(updateError);
    }
}
