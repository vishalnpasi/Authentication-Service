package com.albanero.authservice.service;

import com.albanero.authservice.common.dto.request.CustomRole;
import com.albanero.authservice.common.dto.request.ModuleRequestDto;
import com.albanero.authservice.common.dto.request.RolePermissionsListDto;
import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.response.BaseResponse;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;

public interface PermissionService {

    BaseResponse feedEndPoints(HttpServletRequest request, RolePermissionsListDto rolePermissions);

    BaseResponse getRoles();

    BaseResponse getRolePermissions(Optional<String> roleName);

    BaseResponse getPermissions();

    BaseResponse saveCustomRole(HttpServletRequest request, CustomRole customRole);

    BaseResponse subModulesToPermission();

    BaseResponse getPermissionTree();

    BaseResponse getRole(HttpServletRequest request, String roleId);

    BaseResponse updateRole(HttpServletRequest request, String roleId, CustomRole customRole);

    BaseResponse createModule(HttpServletRequest httpServletRequest, ModuleRequestDto modules);

    BaseResponse editModule(HttpServletRequest httpServletRequest, ModuleRequestDto modules, String moduleName);

    BaseResponse fetchModule(String moduleId);

    BaseResponse permissionModules(HttpServletRequest httpServletRequest, Integer page, Integer perPage);

    BaseResponse revampViewDownloadFile();

    List<BaseResponse> detachPermissionFromRole(List<DetachPermissionRequest> detachPermissionRequestList);

    List<BaseResponse> detachApiFromPermission(List<DetachApiRequest> detachApiRequest);

    List<BaseResponse> detachApiFromAllPermissionsOrUpdateApi(List<RemoveOrUpdatePlatformApiDetailsDto> removeOrUpdatePlatformApiDetailsDto);

    BaseResponse renameSubModule(RenameSubModuleRequest renameSubModuleRequest);

    List<BaseResponse> deleteSubModule(List<DeleteSubModuleRequest> deleteSubModuleRequestList);

    List<BaseResponse> deleteModule(List<String> deleteModuleRequestList);

    List<BaseResponse> deleteRole(List<String> deleteRoleRequestList);

    List<BaseResponse> deletePermission(List<DeletePermissionRequest> deletePermissionsRequestList);

    List<BaseResponse> deletePlatformApiDetails(List<DeletePlatformApiDetailsRequest> deletePermissionsRequestList);

}
