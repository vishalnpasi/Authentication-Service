package com.albanero.authservice.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
@Schema(description = "The persistent class for Product Role Details.")
public class ProductRoleDetails {
	String productId;
	String role;
}
