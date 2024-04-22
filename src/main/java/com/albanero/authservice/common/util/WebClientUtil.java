package com.albanero.authservice.common.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.StopWatch;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Class that provide static methods for performing WebClient calls
 * 
 */
@Component
public class WebClientUtil {

	private static final String USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36";

	private final WebClient.Builder webClientBuilder;

	@Autowired
	public WebClientUtil(WebClient.Builder webClientBuilder) {
		this.webClientBuilder = webClientBuilder;
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
	public <T> ResponseEntity<T> get(String url, String token, Class<T> mappingClass) {

		final StopWatch stopWatch = new StopWatch();
		stopWatch.start();

		ResponseEntity<T> responseEntity;
		if (!StringUtils.hasLength(url)) {
			return null;
		}
		if (StringUtils.hasLength(token)) {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.AUTHORIZATION, token)
					.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().get().uri(url).retrieve()
					.toEntity(mappingClass).block();
		} else {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().get().uri(url).retrieve()
					.toEntity(mappingClass).block();
		}

		stopWatch.stop();

		return responseEntity;
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
	 * @return
	 */
	public <T, V> ResponseEntity<T> post(String url, String token, V body, Class<T> mappingClass) {

		final StopWatch stopWatch = new StopWatch();
		stopWatch.start();
		ResponseEntity<T> responseEntity;
		if (!StringUtils.hasLength(url)) {
			return null;
		}
		if (StringUtils.hasLength(token)) {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.AUTHORIZATION, token)
					.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().post().uri(url).bodyValue(body)
					.retrieve().toEntity(mappingClass).block();
		} else {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().post().uri(url).bodyValue(body)
					.retrieve().toEntity(mappingClass).block();
		}
		stopWatch.stop();

		return responseEntity;
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
	 * @return
	 */
	public <T, V> ResponseEntity<T> patch(String url, String token, V body, Class<T> mappingClass) {

		final StopWatch stopWatch = new StopWatch();
		stopWatch.start();
		ResponseEntity<T> responseEntity;
		if (!StringUtils.hasLength(url)) {
			return null;
		}
		if (StringUtils.hasLength(token)) {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.AUTHORIZATION, token)
					.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().patch().uri(url).bodyValue(body)
					.retrieve().toEntity(mappingClass).block();
		} else {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().patch().uri(url).bodyValue(body)
					.retrieve().toEntity(mappingClass).block();
		}

		stopWatch.stop();

		return responseEntity;
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
	 * @return
	 */
	public <T, V> ResponseEntity<T> put(String url, String token, V body, Class<T> mappingClass) {

		final StopWatch stopWatch = new StopWatch();
		stopWatch.start();
		ResponseEntity<T> responseEntity;
		if (!StringUtils.hasLength(url)) {
			return null;
		}
		if (StringUtils.hasLength(token)) {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.AUTHORIZATION, token)
					.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().put().uri(url).bodyValue(body).retrieve()
					.toEntity(mappingClass).block();
		} else {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().put().uri(url).bodyValue(body).retrieve()
					.toEntity(mappingClass).block();
		}
		stopWatch.stop();

		return responseEntity;
	}

	/**
	 * method handles DELETE request
	 * 
	 * @param <T>          Generic Type for Response (Required)
	 * @param url          Rest API URL (Required)
	 * @param token        Authentication token only required if API need it.
	 *                     (Optional)
	 * @param mappingClass Class Type to which Response need to be mapped (Required)
     */
	public <T> ResponseEntity<T> delete(String url, String token, Class<T> mappingClass) {

		final StopWatch stopWatch = new StopWatch();
		stopWatch.start();
		ResponseEntity<T> responseEntity;
		if (!StringUtils.hasLength(url)) {
			return null;
		}
		if (StringUtils.hasLength(token)) {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.AUTHORIZATION, token)
					.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().delete().uri(url).retrieve()
					.toEntity(mappingClass).block();
		} else {
			responseEntity = webClientBuilder.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
					.defaultHeader(HttpHeaders.USER_AGENT, USER_AGENT).build().delete().uri(url).retrieve()
					.toEntity(mappingClass).block();
		}

		stopWatch.stop();

		return responseEntity;
	}

}
