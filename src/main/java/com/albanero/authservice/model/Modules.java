package com.albanero.authservice.model;

import com.albanero.authservice.common.dto.response.CreatedDetailsDto;
import com.albanero.authservice.common.dto.response.UpdatedDetailsDto;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import jakarta.validation.constraints.NotBlank;
import java.time.ZonedDateTime;

@Data
@Document(collection = "modules")
public class Modules {
    @Id
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
