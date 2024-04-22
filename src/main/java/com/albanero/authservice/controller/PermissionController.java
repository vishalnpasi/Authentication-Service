package com.albanero.authservice.controller;

import com.albanero.authservice.common.constants.MappingConstants;
import com.albanero.authservice.common.constants.PathVariables;
import com.albanero.authservice.common.constants.PermissionMappingConstants;
import com.albanero.authservice.common.constants.RequestParams;
import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.request.CustomRole;
import com.albanero.authservice.common.dto.request.ModuleRequestDto;
import com.albanero.authservice.common.dto.request.RolePermission;
import com.albanero.authservice.common.dto.request.RolePermissionsListDto;
import com.albanero.authservice.common.dto.response.BaseResponse;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.model.Modules;
import com.albanero.authservice.service.PermissionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Optional;

import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_END_LOG_TAG;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_START_LOG_TAG;

@RestController
@RequestMapping(MappingConstants.API_USER_BASE)
public class PermissionController {

    private static final Logger LOGGER = LoggerFactory.getLogger(PermissionController.class);

    private static final String PERMISSION_CONTROLLER = "PermissionController";

    private final PermissionService permissionService;

    @Autowired
    public PermissionController(PermissionService permissionService) {
        this.permissionService = permissionService;
    }

    /**
     * This Method is to feed the endpoints for a permission for a role
     *
     * @param request        {@link HttpServletRequest}
     * @param rolePermissions {@link RolePermission}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(PermissionMappingConstants.FEED_ENDPOINT)
    public ResponseEntity<BaseResponse> feedEndpoints(
            HttpServletRequest request,
            @Valid @RequestBody RolePermissionsListDto rolePermissions
    ) {
        String method = "feedEndpoints";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.feedEndPoints(request, rolePermissions);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);

    }

    /**
     * This method is used to return all the roles with their permissions and endpoints
     *
     * @param roleName {@link Optional<String>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(PermissionMappingConstants.GET_ROLE_PERMISSIONS)
    public ResponseEntity<BaseResponse> getRolePermissions(@RequestParam("roleName") Optional<String> roleName) {
        String method = "getRolePermissions";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.getRolePermissions(roleName);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);

    }

    /**
     * This method is used to return all the roles
     *
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(PermissionMappingConstants.GET_ROLES)
    public ResponseEntity<BaseResponse> getRoles() {
        String method = "getRoles";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.getRoles();
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);

    }

    /**
     * Api to fetch all permissions
     *
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(PermissionMappingConstants.GET_PERMISSIONS)
    public ResponseEntity<BaseResponse> permissions() {
        String method = "permissions";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.getPermissions();
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return ResponseEntity.ok(baseResponse);
    }

    /**
     * Api to save a user defined role all permissions
     *
     * @param request    {@link HttpServletRequest}
     * @param customRole {@link CustomRole}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(PermissionMappingConstants.USER_ROLES)   ///still pending
    public ResponseEntity<BaseResponse> customRoles(@Valid HttpServletRequest request, @RequestBody CustomRole customRole) {
        String method = "customRoles";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.saveCustomRole(request, customRole);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to get specific role with its permissions
     *
     * @param request {@link HttpServletRequest}
     * @param roleId  {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(PermissionMappingConstants.USER_ROLES + PathVariables.ROLE_ID)
    public ResponseEntity<BaseResponse> getRole(
            HttpServletRequest request,
            @PathVariable(RequestParams.ROLE_ID) String roleId
    ) {
        String method = "getRole";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.getRole(request, roleId);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to update the role details
     *
     * @param request    {@link HttpServletRequest}
     * @param customRole {@link CustomRole}
     * @param roleId     {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PutMapping(PermissionMappingConstants.USER_ROLES + PathVariables.ROLE_ID)
    public ResponseEntity<BaseResponse> updateRole(
            @Valid HttpServletRequest request,
            @RequestBody CustomRole customRole,
            @PathVariable(RequestParams.ROLE_ID) String roleId
    ) {
        String method = "updateRole";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.updateRole(request, roleId, customRole);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    @PostMapping("/add-submodules-to permission")
    public ResponseEntity<BaseResponse> subModulesToPermission() {
        String method = "subModulesToPermission";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        BaseResponse baseResponse = permissionService.subModulesToPermission();
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);

    }

    @GetMapping(PermissionMappingConstants.PERMISSION_TREE)
    public ResponseEntity<BaseResponse> getPermissionTree() {
        String method = "getPermissionTree";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.getPermissionTree();
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to create permission modules
     *
     * @param request {@link HttpServletRequest}
     * @param modules {@link Modules}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(PermissionMappingConstants.PERMISSION_MODULES)
    public ResponseEntity<BaseResponse> createModule(HttpServletRequest request, @Valid @RequestBody ModuleRequestDto modules) {
        String method = "createModule";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.createModule(request, modules);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to edit permission modules
     *
     * @param request {@link HttpServletRequest}
     * @param modules {@link Modules}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PutMapping(PermissionMappingConstants.PERMISSION_MODULES)
    public ResponseEntity<BaseResponse> editModule(
            HttpServletRequest request,
            @Valid @RequestBody ModuleRequestDto modules,
            @RequestParam(RequestParams.PERMISSION_MODULE_NAME) String moduleName
    ) {
        String method = "editModule";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.editModule(request, modules, moduleName);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);

    }

    /**
     * Api to fetch permission module
     *
     * @param moduleId {@link String}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(PermissionMappingConstants.PERMISSION_MODULES + PathVariables.PERMISSION_MODULE_ID)
    public ResponseEntity<BaseResponse> fetchModule(@PathVariable(RequestParams.PERMISSION_MODULE_ID) String moduleId) {
        String method = "fetchModule";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.fetchModule(moduleId);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);

    }

    /**
     * Api to get all permission modules
     *
     * @param request {@link HttpServletRequest}
     * @param perPage {@link Integer}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @GetMapping(PermissionMappingConstants.PERMISSION_MODULES)
    public ResponseEntity<BaseResponse> permissionModules(
            HttpServletRequest request,
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "10") int perPage
    ) {
        String method = "permissionModules";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.permissionModules(request, page, perPage);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    @GetMapping("/revamp-view-download-file")
    public ResponseEntity<BaseResponse> revampViewDownloadFile() {
        String method = "revampViewDownloadFile";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.revampViewDownloadFile();
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to detach permission from role
     *
     * @param detachPermissionRequestList {@link List<DetachPermissionRequest>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(PermissionMappingConstants.DETACH_PERMISSION_FROM_ROLE)
    public ResponseEntity<List<BaseResponse>> detachPermissionFromRole(@RequestBody List<DetachPermissionRequest> detachPermissionRequestList){
        String method = "detachPermissionFromRole";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        List<BaseResponse> baseResponse = permissionService.detachPermissionFromRole(detachPermissionRequestList);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to detach platformApiRole from permission
     *
     * @param detachApiRequestList {@link List<DetachApiRequest>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(PermissionMappingConstants.DETACH_API_FROM_PERMISSION)
    public ResponseEntity<List<BaseResponse>> detachApiFromPermission(@RequestBody List<DetachApiRequest> detachApiRequestList){
        String method = "detachApiFromPermission";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        List<BaseResponse> baseResponse = permissionService.detachApiFromPermission(detachApiRequestList);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to remove platformApiRole from all permission or update platformApiDetails
     *
     * @param removeOrUpdatePlatformApiDetailsDtoList {@link List<RemoveOrUpdatePlatformApiDetailsDto>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PostMapping(PermissionMappingConstants.REMOVE_OR_UPDATE_API_FROM_ALL_PERMISSIONS)
    public ResponseEntity<List<BaseResponse>> detachApiFromAllPermissionsOrUpdateApi(@RequestBody List<RemoveOrUpdatePlatformApiDetailsDto> removeOrUpdatePlatformApiDetailsDtoList){
        String method = "detachApiFromAllPermissionsOrUpdateApi";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        List<BaseResponse> baseResponse = permissionService.detachApiFromAllPermissionsOrUpdateApi(removeOrUpdatePlatformApiDetailsDtoList);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to update sub-domain.
     *
     * @param renameSubModuleRequest {@link RenameSubModuleRequest}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @PutMapping(PermissionMappingConstants.UPDATE_SUBDOMAIN)
    public ResponseEntity<BaseResponse> updateSubModule(@RequestBody RenameSubModuleRequest renameSubModuleRequest){
        String method = "updateSubModule";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        BaseResponse baseResponse = permissionService.renameSubModule(renameSubModuleRequest);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return HelperUtil.getResponseEntity(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to update sub-domain.
     *
     * @param deleteSubModuleRequestList {@link List<DeleteSubModuleRequest>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @DeleteMapping(PermissionMappingConstants.SUBMODULE)
    public ResponseEntity<List<BaseResponse>> deleteSubModule(@RequestBody List<DeleteSubModuleRequest> deleteSubModuleRequestList){
        String method = "updateSubModule";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        List<BaseResponse> baseResponse = permissionService.deleteSubModule(deleteSubModuleRequestList);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to delete domain and detach module and submodule from permissions.
     *
     * @param deleteModuleRequestList {@link List<String>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @DeleteMapping(PermissionMappingConstants.MODULE)
    public ResponseEntity<List<BaseResponse>> deleteModule(@RequestBody List<String> deleteModuleRequestList){
        String method = "deleteModule";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        List<BaseResponse> baseResponse = permissionService.deleteModule(deleteModuleRequestList);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to delete roles and detach it from userOrgRole.
     *
     * @param deleteRoleRequestList {@link List<String>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @DeleteMapping(PermissionMappingConstants.GET_ROLES)
    public ResponseEntity<List<BaseResponse>> deleteRole(@RequestBody List<String> deleteRoleRequestList){
        String method = "deleteRole";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        List<BaseResponse> baseResponse = permissionService.deleteRole(deleteRoleRequestList);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to delete permissions and detach it from role.
     *
     * @param deletePermissionsRequestList {@link List<DeletePermissionRequest>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @DeleteMapping(PermissionMappingConstants.GET_PERMISSIONS)
    public ResponseEntity<List<BaseResponse>> deletePermissions(@RequestBody List<DeletePermissionRequest> deletePermissionsRequestList) {
        String method = "deletePermissions";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        List<BaseResponse> baseResponse = permissionService.deletePermission(deletePermissionsRequestList);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }

    /**
     * Api to delete platformApiDetails and detach it from permissions.
     *
     * @param deletePlatformApiDetailsRequestList {@link List<DeletePlatformApiDetailsRequest>}
     * @return {@link ResponseEntity<BaseResponse>}
     */
    @DeleteMapping(PermissionMappingConstants.PLATFORM_API_DETAILS)
    public ResponseEntity<List<BaseResponse>> deletePlatformApiDetails(@RequestBody List<DeletePlatformApiDetailsRequest> deletePlatformApiDetailsRequestList) {
        String method = "deletePlatformApiDetails";
        LOGGER.info(AUTHENTICATION_SERVICE_START_LOG_TAG,PERMISSION_CONTROLLER,method);
        long startTime = System.currentTimeMillis();
        List<BaseResponse> baseResponse = permissionService.deletePlatformApiDetails(deletePlatformApiDetailsRequestList);
        LOGGER.info(AUTHENTICATION_SERVICE_END_LOG_TAG,PERMISSION_CONTROLLER,method, (System.currentTimeMillis() - startTime));
        return new ResponseEntity<>(baseResponse, HttpStatus.OK);
    }


}
