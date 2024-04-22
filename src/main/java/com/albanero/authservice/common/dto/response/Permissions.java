package com.albanero.authservice.common.dto.response;

import lombok.Data;

@Data
public class Permissions {
	String route;
	Boolean view;
	Boolean write;
	Boolean hasSideBarAccess;
	Boolean subRoutesSecure;
}
