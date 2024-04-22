package com.albanero.authservice.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Data;

/**
 * Fetch Response DTO class for fetch request Details REST API Call
 */

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
@Schema(description = "Fetch Response DTO class for fetch request Details REST API Call")
public class FetchResponse {

	@Schema(description = "IP address of device from which request was sent")
	private String ip;
	@Schema(description = "Country of device from which request was sent")
	private String country;
	@Schema(description = "Subdivision of device from which request was sent")
	private String subDivision;
	@Schema(description = "City of device from which request was sent")
	private String city;
	@Schema(description = "Postal Code of device from which request was sent")
	private String postalCode;
	@Schema(description = "Latitude of device from which request was sent")
	private Double latitude;
	@Schema(description = "Longitude of device from which request was sent")
	private Double longitude;
	@Schema(description = "Time Zone of device from which request was sent")
	private String timeZone;
	@Schema(description = "Device Type of device from which request was sent")
	private String deviceType;
	@Schema(description = "Operating System of device from which request was sent")
	private String os;
	@Schema(description = "Browser of device from which request was sent")
	private String browser;
	@Schema(description = "Referer of device from which request was sent")
	private String referer;
	@Schema(description = "Sockket Number of device from which request was sent")
	private String socketNumber;
	@Schema(description = "MAC address of device from which request was sent")
	private String mac;

}
