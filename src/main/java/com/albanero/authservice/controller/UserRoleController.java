package com.albanero.authservice.controller;

import com.albanero.authservice.common.constants.*;
import com.albanero.authservice.common.dto.request.ApiDetails;
import com.albanero.authservice.common.dto.request.AuthRequest;
import com.albanero.authservice.common.dto.request.UserProfileDetails;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.service.UserRoleService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.ACTION_FAILED_EXCEPTION;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_END_LOG_TAG;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_START_LOG_TAG;

@RestController
@RequestMapping(MappingConstants.API_USER_BASE)
public class UserRoleController {
    private static final Logger LOGGER = LoggerFactory.getLogger(UserRoleController.class);

    private static final String USER_ROLE_CONTROLLER = "UserRoleController";

    private final UserRoleService userRoleService;

    @Autowired
    public UserRoleController(UserRoleService userRoleService) {
        this.userRoleService = userRoleService;
    }

    /**
     * REST API responsible for fetching user Roles of organization and projects.
     *
     * @param authRequest    {@link AuthRequest}
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(UserMappingConstants.FETCH_USER_MAPPINGS)
    public ResponseEntity<BaseResponse> getUserMappings(HttpServletRequest request, @RequestBody AuthRequest authRequest) {
        String method = "getUserMappings";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_ROLE_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
		BaseResponse baseResponse = userRoleService.getUserMappings(request, authRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_ROLE_CONTROLLER, method, (System.currentTimeMillis() - startTime));
        if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.UNAUTHORIZED.toString())){
			return new ResponseEntity<>(baseResponse, HttpStatus.FORBIDDEN);
		}
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * REST API responsible for checking user have right to access particular endpoint.
     *
     * @param apiDetails    {@link ApiDetails}
     * @param request {@link HttpServletRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(AuthConstants.AUTHORIZE_API_ROUTES)
    public ResponseEntity<BaseResponse> authorizeApiRoutes(HttpServletRequest request, @Valid @RequestBody ApiDetails apiDetails) {
        String method = "authorizeApiRoutes";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_ROLE_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userRoleService.authorizeApiRoutes(request, apiDetails);
            LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_ROLE_CONTROLLER, method, (System.currentTimeMillis() - startTime));
            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.UNAUTHORIZED.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.FORBIDDEN);

            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.BAD_REQUEST.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.BAD_REQUEST);

            return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * API to update existing user roles in project
     *
     * @param request
     * @param apiDetails
     * @return
     */
    @PutMapping(ProjectConstants.USER_PROJECT_ROLES)
    public ResponseEntity<BaseResponse> updateUserRolesInProject(HttpServletRequest request, @RequestBody UserProfileDetails userProfileDetails) {
        String method = "updateUserRolesInProject";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_ROLE_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userRoleService.updateUserRolesInProject(request, userProfileDetails);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_ROLE_CONTROLLER, method, (System.currentTimeMillis() - startTime));
            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.UNAUTHORIZED.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.FORBIDDEN);

            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.BAD_REQUEST.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.BAD_REQUEST);

            return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * API to update existing user roles in org
     *
     * @param request
     * @param apiDetails
     * @return
     */
    @PutMapping(OrgConstants.USER_ORG_ROLES)
    public ResponseEntity<BaseResponse> updateUserRolesInOrg(HttpServletRequest request, @RequestBody UserProfileDetails userProfileDetails) {
        String method = "updateUserRolesInOrg";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_ROLE_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userRoleService.updateUserRolesInOrg(request, userProfileDetails);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_ROLE_CONTROLLER, method, (System.currentTimeMillis() - startTime));
            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.FORBIDDEN.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.FORBIDDEN);

            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.BAD_REQUEST.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.BAD_REQUEST);

            return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }


    @GetMapping("/sync-roles-to-project-org")
    public ResponseEntity<BaseResponse> syncRolesToProjectOrg() {
        String method = "syncRolesToProjectOrg";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_ROLE_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = userRoleService.syncRolesToProjectOrg();
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG, USER_ROLE_CONTROLLER, method, (System.currentTimeMillis() - startTime));
            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.FORBIDDEN.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.FORBIDDEN);

            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.BAD_REQUEST.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.BAD_REQUEST);

            return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    @GetMapping("/add-roles-to-users")
    public ResponseEntity<BaseResponse> addRolesToUsers() {
        String method = "    public ResponseEntity<BaseResponse> addRolesToUsers() {\n";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG, USER_ROLE_CONTROLLER, method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        try {
            baseResponse = userRoleService.addRolesToUsers();
            LOGGER.info("Time taken by UserRoleController::addRolesToUsers {}", (System.currentTimeMillis() - startTime));
            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.UNAUTHORIZED.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.FORBIDDEN);

            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.BAD_REQUEST.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.BAD_REQUEST);

            return new ResponseEntity<>(baseResponse, HttpStatus.OK);
        } catch (Exception e) {
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.toString());
            baseResponse.setSuccess(false);
            LOGGER.error("Exception occured in adding roles {}", e.getMessage(), e);
            return new ResponseEntity<>(baseResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/add-org-watcher-to-users")
    public ResponseEntity<BaseResponse> addOrgWatcherToUsers() {
        LOGGER.info("Inside UserRoleController::addOrgWatcherToUsers");
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = new BaseResponse();
        try {
            baseResponse = userRoleService.addOrgWatcherToUsers();
            LOGGER.info("Time taken by UserRoleController::addOrgWatcherToUsers {}", (System.currentTimeMillis() - startTime));
            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.UNAUTHORIZED.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.FORBIDDEN);

            if (baseResponse.getStatusCode() != null && baseResponse.getStatusCode().equals(HttpStatus.BAD_REQUEST.toString()))
                return new ResponseEntity<>(baseResponse, HttpStatus.BAD_REQUEST);

            return new ResponseEntity<>(baseResponse, HttpStatus.OK);
        } catch (Exception e) {
            baseResponse.setMessage(ACTION_FAILED_EXCEPTION.toString());
            baseResponse.setSuccess(false);
            LOGGER.error("Exception occured in updating roles {}", e.getMessage(), e);
            return new ResponseEntity<>(baseResponse, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
