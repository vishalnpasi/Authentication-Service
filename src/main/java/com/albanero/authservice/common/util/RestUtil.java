package com.albanero.authservice.common.util;

import java.util.List;

import com.albanero.authservice.common.dto.response.BaseResponse;
import org.springframework.http.*;
import org.springframework.util.StopWatch;
import org.springframework.web.client.RestTemplate;

/**
 * Class that provide static methods for performing REST exchange
 * 
 * @author arunima.mishra
 */
public class RestUtil {

	private static final RestTemplate restTemplate = new RestTemplate();

	/**
	 * method handles all request as per passed parameter and return Generic
	 * Response
	 * 
	 * @param <T>          Generic Type (Required)
	 * @param url          Rest API URL (Required)
	 * @param token        Authentication token only required if API need it.
	 *                     (Optional)
	 * @param body         RequestBody only required if {@link HttpMethod} is POST
	 * @param httpMethod   {@link HttpMethod} (Required)
	 * @param mappingClass Class Type to which Response need to be mapped (Required)
	 * @return Generic Response of given Class Type
	 */
	public static <T> ResponseEntity<T> process(String url, String token, Object body, HttpMethod httpMethod,
			Class<T> mappingClass) {

		final StopWatch stopWatch = new StopWatch();
		stopWatch.start();

		if (isEmpty(url) || httpMethod == null) {
			return null;
		}
		ResponseEntity<T> responseEntity = restTemplate.exchange(url, httpMethod, getBody(getHeaders(token), body),
				mappingClass);

		stopWatch.stop();


		return responseEntity;
	}

	/**
	 * method handles GET request
	 * 
	 * @param <T>          Generic Type (Required)
	 * @param url          Rest API URL (Required)
	 * @param token        Authentication token only required if API need it.
	 *                     (Optional)
	 * @param mappingClass Class Type to which Response need to be mapped (Required)
	 * @return Generic Response of given Class Type
	 */
	public static <T> ResponseEntity<T> get(String url, String token, Class<T> mappingClass) {
		if (isEmpty(url)) {
			return null;
		}
		return process(url, token, null, HttpMethod.GET, mappingClass);
	}

	/**
	 * method handles POST request
	 * 
	 * @param <T>          Generic Type for Response (Required)
	 * @param <V>          Generic Type for Request body (Required)
	 * @param url          Rest API URL (Required)
	 * @param token        token Authentication token only required if API need it.
	 *                     (Optional)
	 * @param body         RequestBody (Required)
	 * @param mappingClass Class Type to which Response need to be mapped (Required)
	 * @return Generic Response of given Class Type
	 */
	public static <T, V> ResponseEntity<T> post(String url, String token, V body, Class<T> mappingClass) {
		if (isEmpty(url)) {
			return null;
		}
		return process(url, token, body, HttpMethod.POST, mappingClass);
	}

	/**
	 * method handles PATCH request
	 * 
	 * @param <T>          Generic Type for Response (Required)
	 * @param <V>          Generic Type for Request body (Required)
	 * @param url          Rest API URL (Required)
	 * @param token        token Authentication token only required if API need it.
	 *                     (Optional)
	 * @param body         RequestBody (Required)
	 * @param mappingClass Class Type to which Response need to be mapped (Required)
	 * @return Generic Response of given Class Type
	 */
	public static <T, V> ResponseEntity<T> patch(String url, String token, V body, Class<T> mappingClass) {
		if (isEmpty(url)) {
			return null;
		}
		return process(url, token, body, HttpMethod.PATCH, mappingClass);
	}

	/**
	 * method handles PUT request
	 * 
	 * @param <T>          Generic Type for Response (Required)
	 * @param <V>          Generic Type for Request body (Required)
	 * @param url          Rest API URL (Required)
	 * @param token        token Authentication token only required if API need it.
	 *                     (Optional)
	 * @param body         RequestBody (Required)
	 * @param mappingClass Class Type to which Response need to be mapped (Required)
	 * @return Generic Response of given Class Type
	 */
	public static <T, V> ResponseEntity<T> put(String url, String token, V body, Class<T> mappingClass) {
		if (isEmpty(url)) {
			return null;
		}
		return process(url, token, body, HttpMethod.PUT, mappingClass);
	}

	/**
	 * method handles DELETE request
	 * 
	 * @param <T>          Generic Type for Response (Required)
	 * @param url          Rest API URL (Required)
	 * @param token        Authentication token only required if API need it.
	 *                     (Optional)
	 * @param mappingClass Class Type to which Response need to be mapped (Required)
	 * @return Generic Response of given Class Type
	 */
	public static <T> ResponseEntity<T> delete(String url, String token, Class<T> mappingClass) {
		if (isEmpty(url)) {
			return null;
		}
		return process(url, token, null, HttpMethod.DELETE, mappingClass);
	}

	/**
	 * method provide {@link HttpHeaders} after adding given token and required
	 * headers
	 * 
	 * @param token Authentication token only required if API need it. (Optional)
	 * @return {@link HttpHeaders}
	 */
	private static HttpHeaders getHeaders(String token) {

		HttpHeaders requestHeaders = new HttpHeaders();

		if (!isEmpty(token)) {
			requestHeaders.add(HttpHeaders.AUTHORIZATION, token);
		}
		requestHeaders.add(HttpHeaders.USER_AGENT,
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36");
		requestHeaders.setAccept(List.of(MediaType.APPLICATION_JSON));

		return requestHeaders;
	}

	/**
	 * method provide {@link HttpEntity} after adding given headers and body
	 * 
	 * @param headers {@link HttpHeaders} (Optional)
	 * @param body    Object (Optional)
	 * @return {@link HttpEntity} after adding given parameters
	 */
	private static HttpEntity<Object> getBody(HttpHeaders headers, Object body) {

		if (body == null && headers == null) {
			return null;
		}

		if (headers == null) {
			return new HttpEntity<>(body);
		}

		if (body == null) {
			return new HttpEntity<>(headers);
		}

		return new HttpEntity<>(body, headers);
	}

	/**
	 * Method to validate BaseResponse and return ResponseEntity
	 *
	 * @param baseResponse {@link BaseResponse}
	 * @param status {@link HttpStatus}
	 * @return {@link ResponseEntity<BaseResponse>}
	 */
	public static ResponseEntity<BaseResponse> getResponseEntity(BaseResponse baseResponse, HttpStatus status) {
		if (baseResponse != null && baseResponse.getStatusCode() != null) {
			HttpStatus httpStatus = HttpStatus.resolve(Integer.parseInt(baseResponse.getStatusCode()));
			baseResponse.setStatusCode(null);
			if (httpStatus != null) return new ResponseEntity<>(baseResponse, httpStatus);
		}
		if (baseResponse != null) baseResponse.setStatusCode(null);
		return new ResponseEntity<>(baseResponse, status);
	}

	public static boolean isEmpty(String str) {
		return str == null || str.isBlank();
	}
	private RestUtil() {
		throw new IllegalStateException("RestUtil class");
	}

}
