package com.albanero.authservice.common.dto.request;

import com.albanero.authservice.common.dto.response.CreatedDetailsDto;
import com.albanero.authservice.common.dto.response.UpdatedDetailsDto;
import com.albanero.authservice.model.UserProfile;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;
import java.time.ZonedDateTime;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ModuleRequestDto {
    String id;
    @NotBlank
    private String moduleName;
    private CreatedDetailsDto created;
    private UpdatedDetailsDto updated;

    public void setCreated (UserProfile userProfile) {
        CreatedDetailsDto createdDetails = new CreatedDetailsDto();
        createdDetails.setCreatedById(userProfile.getId());
        createdDetails.setCreatedByUserName(userProfile.getUsername());
        createdDetails.setCreatedAt(ZonedDateTime.now().toInstant().toEpochMilli());

        this.created = createdDetails;
    }

    public void setUpdated (UserProfile userProfile) {
        UpdatedDetailsDto updatedDetails = new UpdatedDetailsDto();
        updatedDetails.setUpdatedById(userProfile.getId());
        updatedDetails.setUpdatedByUserName(userProfile.getUsername());
        updatedDetails.setUpdatedAt(ZonedDateTime.now().toInstant().toEpochMilli());

        this.updated = updatedDetails;
    }

}
