package com.albanero.authservice.service.impl;

import com.albanero.authservice.common.constants.PermissionConstants;
import com.albanero.authservice.common.dto.request.*;
import com.albanero.authservice.common.dto.response.RolePermissions;
import com.albanero.authservice.common.dto.response.*;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.exception.PermissionServiceException;
import com.albanero.authservice.model.Permissions;
import com.albanero.authservice.model.*;
import com.albanero.authservice.repository.*;
import com.albanero.authservice.service.PermissionService;
import com.albanero.authservice.service.impl.rolepermissions.ModulesPermissionsHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.*;

@Service
public class PermissionServiceImpl implements PermissionService {

    private final PermissionsRepository permissionsRepository;

    private final RoleRepository roleRepository;

    private final PlatformApiDetailsRepository platformApiDetailsRepository;

    private final HelperUtil helperUtil;

    private final ModuleRepository moduleRepository;

    private final SubModuleRepository subModuleRepository;

    private final ModulesPermissionsHelper modulesPermissionsHelper;

    private final OrgRoleRepository orgRoleRepository;

    private final ProjectOrgRoleRepository projectOrgRoleRepository;

    private final UserOrgRoleRepository userOrgRoleRepository;



    @Autowired
    public PermissionServiceImpl(PermissionsRepository permissionsRepository, RoleRepository roleRepository, PlatformApiDetailsRepository platformApiDetailsRepository, HelperUtil helperUtil, ModuleRepository moduleRepository, SubModuleRepository subModuleRepository, ModulesPermissionsHelper modulesPermissionsHelper, OrgRoleRepository orgRoleRepository, ProjectOrgRoleRepository projectOrgRoleRepository, UserOrgRoleRepository userOrgRoleRepository) {
        this.permissionsRepository = permissionsRepository;
        this.roleRepository = roleRepository;
        this.platformApiDetailsRepository = platformApiDetailsRepository;
        this.helperUtil = helperUtil;
        this.moduleRepository = moduleRepository;
        this.subModuleRepository = subModuleRepository;
        this.modulesPermissionsHelper = modulesPermissionsHelper;
        this.orgRoleRepository = orgRoleRepository;
        this.projectOrgRoleRepository = projectOrgRoleRepository;
        this.userOrgRoleRepository = userOrgRoleRepository;
    }

    public BaseResponse feedEndPoints(HttpServletRequest request, RolePermissionsListDto rolePermissions) {
        BaseResponse baseResponse = new BaseResponse();
        List<RolePermission> rolePermissionsList = rolePermissions.getRolePermissions();
        for(RolePermission rolePermission : rolePermissionsList){

        
        Modules modules = moduleRepository.findByModuleName(rolePermission.getModule());
        UserProfile userProfile = helperUtil.getUserProfileFromRequest(request);
        SubModules subModules = new SubModules();

            modules = getModules(rolePermission, modules, userProfile);

            if (!Objects.isNull(rolePermission.getSubModule())) {

            subModules = subModuleRepository.findBySubModuleNameAndModuleId(rolePermission.getSubModule(), modules.getId());
                subModules = getSubModules(rolePermission, subModules, modules);
            }

        String permissionId;
        Permissions inputPermissions = rolePermission.getPermissionDetails();
        String roleName = rolePermission.getRoleName();
        Role dbRole = roleRepository.findByRoleName(roleName);

        if (Objects.isNull(dbRole)) {
            throw new PermissionServiceException(ROLE_NOT_EXIST_EXCEPTION.label,HttpStatus.BAD_REQUEST);
        }

        List<PlatformApiDetails> platformApiDetails = rolePermission.getPlatformApiDetails();

            validatePlatformApiDetails(platformApiDetails);
            Permissions dbPermission;
        if (!Objects.isNull(rolePermission.getSubModule())) {
            dbPermission = permissionsRepository.findByPermissionTitleAndModuleIdAndSubModuleId(inputPermissions.getPermissionTitle(), modules.getId(), subModules.getId());
        } else {
            dbPermission = permissionsRepository.findByPermissionTitleAndModuleId(inputPermissions.getPermissionTitle(), modules.getId());
        }

            permissionId = getPermissionId(rolePermission, dbPermission, platformApiDetails, inputPermissions, modules, subModules);

            List<String> permissionList = dbRole.getPermissionIdList();
        if (!permissionList.contains(permissionId)) {
            permissionList.add(permissionId);
        }
        dbRole.setPermissionIdList(permissionList);
        roleRepository.save(dbRole);
    }

        baseResponse.setMessage("Role Permission Endpoint added successfully");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private static void validatePlatformApiDetails(List<PlatformApiDetails> platformApiDetails) {
        for (PlatformApiDetails platformApiDetail : platformApiDetails) {
            if (!HelperUtil.isValidRegex(platformApiDetail.getApiRoute())) {
                throw new PermissionServiceException(INVALID_ROUTE_REGEX_EXCEPTION.label,HttpStatus.BAD_REQUEST);
            }
            if (!HelperUtil.isValidApiMethod(platformApiDetail.getApiMethod().toUpperCase())) {
                throw new PermissionServiceException(INVALID_API_METHOD_EXCEPTION.label,HttpStatus.BAD_REQUEST);
            }
        }
    }

    private String getPermissionId(RolePermission rolePermission, Permissions dbPermission, List<PlatformApiDetails> platformApiDetails, Permissions inputPermissions, Modules modules, SubModules subModules) {
        String permissionId;
        if (dbPermission != null) {
            List<String> allowedEndpointIdList = addExistingEndPointsToPermission(dbPermission.getAllowedEndpointIdList(), platformApiDetails);
            dbPermission.setAllowedEndpointIdList(allowedEndpointIdList);
            dbPermission.setDescription(inputPermissions.getDescription());
            permissionsRepository.save(dbPermission);
            permissionId = dbPermission.getId();
        } else {
            Permissions permission = new Permissions();
            permission.setPermission(helperUtil.getPermissionName(modules, subModules, rolePermission.getPermissionDetails().getPermissionTitle()));
            permission.setScreen(helperUtil.getScreenName(modules, subModules));

            List<String> allowedEndpointIdList = addExistingEndPointsToPermission(permission.getAllowedEndpointIdList(), platformApiDetails);
            permission.setAllowedEndpointIdList(allowedEndpointIdList);
            permission.setModuleId(modules.getId());
            if (!Objects.isNull(subModules.getId())) {
                permission.setSubModuleId(subModules.getId());
            }
            permission.setDescription(inputPermissions.getDescription());
            permission.setPermissionTitle(inputPermissions.getPermissionTitle());
            permissionsRepository.save(permission);
            permissionId = permission.getId();
        }
        return permissionId;
    }

    private SubModules getSubModules(RolePermission rolePermission, SubModules subModules, Modules modules) {
        if (!Objects.isNull(subModules)) {
            List<SubModules> subModulesList = subModuleRepository.findByModuleId(modules.getId());
            if (!subModulesList.contains(subModules)) {
                throw new PermissionServiceException(SUB_MODULE_NOT_BELONG_MODULE.label,HttpStatus.BAD_REQUEST);
            }
        } else {
            SubModules newSubModule = new SubModules();
            newSubModule.setSubModuleName(rolePermission.getSubModule());
            newSubModule.setModuleId(modules.getId());
            subModules = subModuleRepository.save(newSubModule);
        }
        return subModules;
    }

    private Modules getModules(RolePermission rolePermission, Modules modules, UserProfile userProfile) {
        if (modules == null) {
            Modules newModule = new Modules();
            newModule.setModuleName(rolePermission.getModule());
            newModule.setCreated(userProfile);
            newModule.setUpdated(userProfile);
            modules = moduleRepository.save(newModule);
        }
        return modules;
    }

    public List<String> addExistingEndPointsToPermission(
            List<String> allowedEndpointIdList,
            List<PlatformApiDetails> platformApiDetails
    ) {
        for (PlatformApiDetails platformApiDetail : platformApiDetails) {
            PlatformApiDetails dbPlatformApiDetails = platformApiDetailsRepository
                    .findIdByApiRouteAndApiMethod(
                            platformApiDetail.getApiRoute(),
                            platformApiDetail.getApiMethod()
                    );
            if (dbPlatformApiDetails != null && allowedEndpointIdList != null && !allowedEndpointIdList.contains(dbPlatformApiDetails.getId())) {
                allowedEndpointIdList.add(dbPlatformApiDetails.getId());
            } else if (dbPlatformApiDetails == null) {
                if (allowedEndpointIdList == null) {
                    allowedEndpointIdList = new ArrayList<>();
                }
                platformApiDetail.setApiMethod(platformApiDetail.getApiMethod().toUpperCase());
                PlatformApiDetails newPlatformApi = platformApiDetailsRepository.save(platformApiDetail);
                allowedEndpointIdList.add(newPlatformApi.getId());
            } else if (allowedEndpointIdList == null) {
                allowedEndpointIdList = new ArrayList<>();
                allowedEndpointIdList.add(dbPlatformApiDetails.getId());
            }
        }
        return allowedEndpointIdList;
    }

    public BaseResponse getRolePermissions(Optional<String> roleName) {
        BaseResponse baseResponse = new BaseResponse();
        List<Role> roles = new ArrayList<>();
        if (roleName.isPresent()) {
            String decodeRoleName = URLDecoder.decode(roleName.get(), StandardCharsets.UTF_8);

            Role role = roleRepository.findByRoleName(decodeRoleName);
            roles.add(role);
        } else {
            roles = roleRepository.findAll();
        }

        List<RolePermissions> rolePermissions = new ArrayList<>();

        for (Role role : roles) {
            RolePermissions rolePermission = new RolePermissions();
            List<String> permissionIds = role.getPermissionIdList();
            List<PermissionEndPoints> permissionEndPoints = new ArrayList<>();

            if (!permissionIds.isEmpty()) {
                setPermissionIds(permissionIds, permissionEndPoints);
            }
            rolePermission.setRole(role.getRoleName());
            rolePermission.setPermissionDetails(permissionEndPoints);
            rolePermissions.add(rolePermission);
        }
        baseResponse.setMessage("Role Permission Endpoint fetched successfully");
        baseResponse.setPayload(rolePermissions);
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private void setPermissionIds(List<String> permissionIds, List<PermissionEndPoints> permissionEndPoints) {
        for (String permissionId : permissionIds) {
            PermissionEndPoints permissionEndPoint = new PermissionEndPoints();
            Optional<Permissions> permission = permissionsRepository.findById(permissionId);

            if (permission.isPresent()) {
                List<String> allowedEndpoints = permission.get().getAllowedEndpointIdList();
                List<PlatformApiDetailsResponseDto> platformApiDetailsResponseDtoList = new ArrayList<>();
                for (String allowedEndPoint : allowedEndpoints) {
                    Optional<PlatformApiDetails> platformApiDetails = platformApiDetailsRepository.findById(allowedEndPoint);
                    if (platformApiDetails.isPresent()) {
                        PlatformApiDetailsResponseDto platformApiDetailsResponseDto = new PlatformApiDetailsResponseDto();
                        platformApiDetailsResponseDto.setMethod(platformApiDetails.get().getApiMethod());
                        platformApiDetailsResponseDto.setEndPoint(platformApiDetails.get().getApiRoute());
                        platformApiDetailsResponseDtoList.add(platformApiDetailsResponseDto);
                    }
                }
                permissionEndPoint.setPermissionName(permission.get().getPermission());
                permissionEndPoint.setScreenName(permission.get().getScreen());
                permissionEndPoint.setPlatformApiDetails(platformApiDetailsResponseDtoList);
                permissionEndPoints.add(permissionEndPoint);
            }

        }
    }

    @Override
    public BaseResponse getPermissions() {
        BaseResponse baseResponse = new BaseResponse();
        List<Permissions> permissions = permissionsRepository.findAll();
        baseResponse.setMessage("Permissions Fetched successfully");
        baseResponse.setPayload(permissions);
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    @Override
    public BaseResponse saveCustomRole(HttpServletRequest request, CustomRole customRole) {
        validateCustomRole(customRole, Optional.empty());
        UserProfile userProfile = helperUtil.getUserProfileFromRequest(request);

        Role role = new Role();
        saveCustomRole(customRole, role);
        role.setCreated(userProfile);
        role.setUpdated(userProfile);
        roleRepository.save(role);

        BaseResponse baseResponse = new BaseResponse();
        baseResponse.setMessage("Role added successfully");
        baseResponse.setSuccess(true);
        baseResponse.setStatusCode(String.valueOf(HttpStatus.OK.value()));
        return baseResponse;
    }

    private void saveCustomRole(CustomRole customRole, Role role) {
        role.setRoleType(customRole.getRoleType());
        role.setRoleName(customRole.getRoleName());
        List<String> permissionIdList = modulesPermissionsHelper.getPermissionIdList(customRole.getPermissionTree());

        List<String> defaultPermissionId = modulesPermissionsHelper.getDefaultPermissionId(customRole.getRoleType().getRoleTypeName());
        permissionIdList.addAll(defaultPermissionId);

        role.setPermissionIdList(permissionIdList);
        role.setDescription(customRole.getDescription());
    }

    private void validateCustomRole(CustomRole customRole, Optional<Role> optRole) {
        if (!customRole.getRoleType().getRoleTypeName().equals(PermissionConstants.PROJECT_CUSTOM) && !customRole.getRoleType().getRoleTypeName().equals(PermissionConstants.ORGANIZATION_CUSTOM)) {
            throw new PermissionServiceException(CUSTOM_ROLE_TYPE_EXCEPTION.label,HttpStatus.BAD_REQUEST);
        }
        if (Objects.isNull(customRole.getDescription()) || customRole.getDescription().isBlank()) {
            throw new PermissionServiceException(ROLE_DESCRIPTION_NULL_EXCEPTION.label,HttpStatus.BAD_REQUEST);
        }
        if (optRole.isEmpty()) {
            Role existingRole = roleRepository.findByRoleName(customRole.getRoleName());
            if (!Objects.isNull(existingRole)) {
                throw new PermissionServiceException(DUPLICATE_ROLE_NAME_EXCEPTION.label,HttpStatus.BAD_REQUEST);
            }
        } else {
            Role actualRole = optRole.get();
            if (!actualRole.getRoleName().equals(customRole.getRoleName())) {
                Role existingRole = roleRepository.findByRoleName(customRole.getRoleName());
                if (!Objects.isNull(existingRole)) {
                    throw new PermissionServiceException(DUPLICATE_ROLE_NAME_EXCEPTION.label,HttpStatus.BAD_REQUEST);
                }
            }
        }
    }

    @Override
    public BaseResponse subModulesToPermission() {
        BaseResponse baseResponse = new BaseResponse();
        List<Permissions> permissionsList = permissionsRepository.findAll();
        for (Permissions permissions : permissionsList) {
            String permission = permissions.getPermission();
            String[] splitPermission = permission.split("\\.");
            Integer splitPermissionSize = splitPermission.length;
            if (splitPermissionSize.equals(3)) {

                // saving the module
                String moduleName = helperUtil.getSpaceSeparatedName(splitPermission[0]);
                Modules modules = moduleRepository.findByModuleName(moduleName);
                if (Objects.isNull(modules)) {
                    Modules newModule = new Modules();
                    newModule.setModuleName(moduleName);
                    modules = moduleRepository.save(newModule);
                }

                //saving submodule
                String subModuleName = helperUtil.getSpaceSeparatedName(splitPermission[1]);
                SubModules subModules = subModuleRepository.findBySubModuleName(subModuleName);
                if (Objects.isNull(subModules)) {
                    SubModules newSubModule = new SubModules();
                    newSubModule.setSubModuleName(subModuleName);
                    newSubModule.setModuleId(modules.getId());
                    subModules = subModuleRepository.save(newSubModule);
                }
                permissions.setPermissionTitle(helperUtil.getSpaceSeparatedName(splitPermission[2]));
                permissions.setModuleId(modules.getId());
                permissions.setSubModuleId(subModules.getId());
                permissionsRepository.save(permissions);
            } else if (splitPermissionSize.equals(2)) {
                // saving the module
                String moduleName = helperUtil.getSpaceSeparatedName(splitPermission[0]);
                Modules modules = moduleRepository.findByModuleName(moduleName);
                if (Objects.isNull(modules)) {
                    Modules newModule = new Modules();
                    newModule.setModuleName(moduleName);
                    modules = moduleRepository.save(newModule);
                }

                permissions.setPermissionTitle(helperUtil.getSpaceSeparatedName(splitPermission[1]));
                permissions.setModuleId(modules.getId());
                permissionsRepository.save(permissions);
            } else {
                baseResponse.setMessage("Modules or submodule cannot be separated and linked " + permissions.getPermission());
                baseResponse.setSuccess(false);
                baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.BAD_REQUEST));
                return baseResponse;
            }
        }
        baseResponse.setMessage("Modules or submodule separated and linked successfully");
        baseResponse.setSuccess(true);
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
        return baseResponse;
    }

    @Override
    public BaseResponse getPermissionTree() {
        BaseResponse baseResponse = new BaseResponse();
        List<Modules> modules = moduleRepository.findAll();
        List<ModuleNameDto> permissionTree = new ArrayList<>();
        for (Modules module : modules) {
            if (!module.getModuleName().equals(PermissionConstants.DEFAULT_MODULE)) {
                ModuleNameDto moduleNameDto = new ModuleNameDto();
                moduleNameDto.setLabel(module.getModuleName());
                moduleNameDto.setId(module.getId());
                moduleNameDto.setUniqueLabel(HelperUtil.getHyphenatedName(module.getModuleName()));
                moduleNameDto.setIndeterminate(false);
                moduleNameDto.setIsSelected(false);
                List<SubModules> subModulesList = subModuleRepository.findByModuleId(module.getId());

                if (subModulesList.isEmpty()) {
                    setSubModList(module, moduleNameDto);
                }
                else {
                    setModuleNameSubModules(subModulesList, moduleNameDto);
                }
                permissionTree.add(moduleNameDto);
            }
        }
        baseResponse.setMessage("permission tree fetched successfully");
        baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
        baseResponse.setPayload(permissionTree);
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    private void setModuleNameSubModules(List<SubModules> subModulesList, ModuleNameDto moduleNameDto) {
        List<ModuleNameDto> moduleNameSubModules = new ArrayList<>();
        for (SubModules subModule : subModulesList) {
            ModuleNameDto moduleNameSubModule = new ModuleNameDto();
            moduleNameSubModule.setId(subModule.getId());
            moduleNameSubModule.setIndeterminate(false);
            moduleNameSubModule.setLabel(subModule.getSubModuleName());
            moduleNameSubModule.setUniqueLabel(HelperUtil.getHyphenatedName(subModule.getSubModuleName()));
            moduleNameSubModule.setIsSelected(false);

            List<Permissions> permissions = permissionsRepository.findBySubModuleId(subModule.getId());
            List<ModuleNameDto> moduleNamePermissions = new ArrayList<>();
            for (Permissions permission : permissions) {
                ModuleNameDto moduleNamePermission = new ModuleNameDto();
                moduleNamePermission.setId(permission.getId());
                moduleNamePermission.setIndeterminate(false);
                moduleNamePermission.setLabel(permission.getPermissionTitle());
                moduleNamePermission.setUniqueLabel(HelperUtil.getHyphenatedName(permission.getPermissionTitle()));
                moduleNamePermission.setIsSelected(false);
                moduleNamePermissions.add(moduleNamePermission);
            }
            moduleNameSubModule.setSub(moduleNamePermissions);
            moduleNameSubModules.add(moduleNameSubModule);
        }
        moduleNameDto.setSub(moduleNameSubModules);
    }

    private void setSubModList(Modules module, ModuleNameDto moduleNameDto) {
        List<ModuleNameDto> moduleNamePermissions = new ArrayList<>();
        List<Permissions> permissions = permissionsRepository.findByModuleId(module.getId());
        for (Permissions permission : permissions) {
            ModuleNameDto moduleNamePermission = new ModuleNameDto();
            moduleNamePermission.setId(permission.getId());
            moduleNamePermission.setIndeterminate(false);
            moduleNamePermission.setUniqueLabel(HelperUtil.getHyphenatedName(permission.getPermissionTitle()));
            moduleNamePermission.setLabel(permission.getPermissionTitle());
            moduleNamePermission.setIsSelected(false);
            moduleNamePermissions.add(moduleNamePermission);
        }
        moduleNameDto.setSub(moduleNamePermissions);
    }

    @Override
    public BaseResponse getRole(HttpServletRequest request, String roleId) {
        RolePermissionDetails rolePermissionDetails = new RolePermissionDetails();
        Optional<Role> role = roleRepository.findById(roleId);
        if (role.isPresent()) {
            Role actuallyRole = role.get();
            Set<String> modulesId = modulesPermissionsHelper.getModuleFromRole(actuallyRole);
            Set<String> subModuleId = modulesPermissionsHelper.getSubModulesFromRole(actuallyRole);
            List<ModuleNameDto> permissionTree = modulesPermissionsHelper.permissionTreeFromModules(modulesId, subModuleId, actuallyRole.getPermissionIdList(), false);

            if (actuallyRole.getRoleType().getRoleTypeName().equals(PermissionConstants.PROJECT_CUSTOM) || actuallyRole.getRoleType().getRoleTypeName().equals(PermissionConstants.ORGANIZATION_CUSTOM)) {
                List<OrgLevelDetails> orgLevelDetailsList = modulesPermissionsHelper.getOrganzationProject(actuallyRole.getRoleType().getOrgId(), actuallyRole.getRoleType().getProjectId());
                rolePermissionDetails.setOrganizationDetails(orgLevelDetailsList);
            }
            rolePermissionDetails.setRoleId(roleId);
            rolePermissionDetails.setPermissionTree(permissionTree);
            rolePermissionDetails.setRoleDescription(actuallyRole.getDescription());
            rolePermissionDetails.setRole(actuallyRole.getRoleName());

            BaseResponse baseResponse = new BaseResponse();
            baseResponse.setPayload(rolePermissionDetails);
            baseResponse.setSuccess(true);
            baseResponse.setMessage("Roles details Fetched Successfully");
            baseResponse.setStatusCode(HelperUtil.stringValueHttpStatus(HttpStatus.OK));
            return baseResponse;
        } else {
            throw new PermissionServiceException(ROLE_NOT_EXIST_EXCEPTION.label,HttpStatus.BAD_REQUEST);
        }
    }

    @Override
    public BaseResponse updateRole(HttpServletRequest request, String roleId, CustomRole customRole) {
        Optional<Role> role = roleRepository.findById(roleId);
        UserProfile userProfile = helperUtil.getUserProfileFromRequest(request);
        if (role.isPresent()) {
            Role actualRole = role.get();
            if (!userProfile.getId().equals(actualRole.getCreated().getCreatedById())) {
                throw new PermissionServiceException(UNABLE_UPDATE_ROLE_EXCEPTION.label,HttpStatus.BAD_REQUEST);
            }
            validateCustomRole(customRole, role);
            //if project is removed from the role. Corresponding users should also not have that role
            modulesPermissionsHelper.removeRolesFromProjectAndUsers(customRole.getRoleType().getProjectId(), actualRole);

            saveCustomRole(customRole, actualRole);
            actualRole.setUpdated(userProfile);
            roleRepository.save(actualRole);

            BaseResponse baseResponse = new BaseResponse();
            baseResponse.setMessage("Role updated successfully");
            baseResponse.setSuccess(true);
            baseResponse.setStatusCode(String.valueOf(HttpStatus.OK.value()));
            return baseResponse;
        } else {
            throw new PermissionServiceException(ROLE_NOT_EXIST_EXCEPTION.label,HttpStatus.BAD_REQUEST);
        }
    }

    public BaseResponse getRoles() {
        BaseResponse baseResponse = new BaseResponse();
        List<Role> roles = roleRepository.findAll();
        baseResponse.setMessage("Role Fetched successfully");
        baseResponse.setPayload(roles);
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    @Override
    public BaseResponse createModule(HttpServletRequest httpServletRequest, ModuleRequestDto modules) {
        BaseResponse baseResponse = new BaseResponse();
        UserProfile user = helperUtil.getUserProfileFromRequest(httpServletRequest);
        boolean isDuplicateExists = helperUtil.checkForDuplicateModuleName(modules.getModuleName(), "");
        if (!isDuplicateExists) {
            Modules newModules = new Modules();
            newModules.setModuleName(modules.getModuleName());
            newModules.setCreated(user);
            newModules.setUpdated(user);
            moduleRepository.save(newModules);
            baseResponse.setSuccess(true);
            baseResponse.setPayload(newModules);
            baseResponse.setMessage("Module created successfully");
            return baseResponse;
        }
        baseResponse.setSuccess(false);
        baseResponse.setMessage("Module with same name already exists");
        return baseResponse;
    }

    @Override
    public BaseResponse editModule(HttpServletRequest httpServletRequest, ModuleRequestDto modules, String moduleName) {
        BaseResponse baseResponse = new BaseResponse();
        UserProfile user = helperUtil.getUserProfileFromRequest(httpServletRequest);
        boolean isDuplicateExists = helperUtil.checkForDuplicateModuleName(modules.getModuleName(), moduleName);
        if (Boolean.FALSE.equals(isDuplicateExists)) {
            Modules optModules = moduleRepository.findByModuleName(moduleName);
            if (optModules == null) {
                throw new PermissionServiceException("module");
            }
            Modules newModules = optModules;
            newModules.setModuleName(modules.getModuleName());
            newModules.setUpdated(user);
            moduleRepository.save(newModules);
            baseResponse.setSuccess(true);
            baseResponse.setPayload(newModules);
            baseResponse.setMessage("Module edited successfully");
            return baseResponse;
        }
        baseResponse.setSuccess(false);
        baseResponse.setMessage("Module with same name already exists");
        return baseResponse;
    }

    @Override
    public BaseResponse fetchModule(String moduleId) {
        BaseResponse baseResponse = new BaseResponse();
        boolean isModulePresent = moduleRepository.findById(moduleId).isPresent();
        if (!isModulePresent) {
            baseResponse.setMessage("Module not found");
            baseResponse.setSuccess(true);
            return baseResponse;
        }
        Optional<Modules> optModules = moduleRepository.findById(moduleId);
        if (optModules.isEmpty()) throw new PermissionServiceException("Module not found");
        Modules modules = optModules.get();
        baseResponse.setPayload(modules);
        baseResponse.setMessage("Permission Modules List fetched Successfully.");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    @Override
    public BaseResponse permissionModules(HttpServletRequest httpServletRequest, Integer page, Integer perPage) {
        BaseResponse baseResponse = new BaseResponse();
        Pageable pageable = PageRequest.of(page, perPage, Sort.by("createdAt").descending());
        List<Modules> modulesList = moduleRepository.findAll();
        int start = (int) pageable.getOffset();
        int end = Math.min((start + pageable.getPageSize()), modulesList.size());
        Page<Modules> modulesPage = new PageImpl<>(modulesList.subList(start, end), pageable, modulesList.size());
        baseResponse.setPayload(modulesPage);
        baseResponse.setMessage("Permission Modules List fetched Successfully.");
        baseResponse.setSuccess(true);
        return baseResponse;
    }

    @Override
    public BaseResponse revampViewDownloadFile() {
        BaseResponse baseResponse = new BaseResponse();
        ArrayList<String> removePermissionArrayList = new ArrayList<>();
        removePermissionArrayList.add("630e288fc856de3c329a0aeb");
        removePermissionArrayList.add("630e26c1c856de3c329a0adf");
        removePermissionArrayList.add("62e7e596cdf86e606fbdb558");
        removePermissionArrayList.add("62e124a400f1e20870b4a325");
        removePermissionArrayList.add("62e0e73500f1e20870b4a308");
        removePermissionArrayList.add("62e0e3c100f1e20870b4a2fe");
        removePermissionArrayList.add("62e0e1ad00f1e20870b4a2f3");
        removePermissionArrayList.add("62e0d19600f1e20870b4a2e2");
        removePermissionArrayList.add("62e0c26900f1e20870b4a2cc");
        removePermissionArrayList.add("62f0e1e3f46fb453b2da374a");
        removePermissionArrayList.add("62f110f4f46fb453b2da3750");

        String viewFileDataId = "6240a18fb6ef5b5820ca45f3";

        //remove download file permission, duplicate inpect & repair, duplicate join-table.view file permission, view data permission from connected sources
        List<Role> roleList = roleRepository.findAll();
        for (Role role : roleList) {
            role.getPermissionIdList().removeIf(removePermissionArrayList::contains);
            roleRepository.save(role);
        }

        //remane view file to view job details
        List<Permissions> permissionsList = permissionsRepository.findAll();
        for (Permissions permissions : permissionsList) {
            if (permissions.getPermission().equals("View File")) {
                permissions.setPermission("View Job Details");
                permissions.setDescription("Permission to view the job details");
                permissionsRepository.save(permissions);
            }
        }

        //removing view file data api from permissions, deleting the download permissions, deleting view data from conected source, removing duplicate inpect & repair, duplicate join-table.view file permission
        List<Permissions> permissionsList1 = permissionsRepository.findAll();
        for (Permissions permissions : permissionsList1) {
            permissions.getAllowedEndpointIdList().removeIf(y -> y.equals(viewFileDataId));
            permissionsRepository.save(permissions);

            if (permissions.getPermissionTitle().equals("Download File")) {
                permissionsRepository.delete(permissions);
            }
            if (permissions.getPermissionTitle().equals("View Data")) {
                permissionsRepository.delete(permissions);
            }
            permissionsRepository.deleteById("62f0e1e3f46fb453b2da374a");
            permissionsRepository.deleteById("62f110f4f46fb453b2da3750");
        }

        //adding the required endpoint for removing duplicate join-table.view file
        Optional<Permissions> optPermissions = permissionsRepository.findById("62e0e28000f1e20870b4a2f9");
        if (optPermissions.isEmpty()) throw new PermissionServiceException("not found permission");
        Permissions permissions = optPermissions.get();
        permissions.getAllowedEndpointIdList().add("62f110f4f46fb453b2da3751");
        permissionsRepository.save(permissions);

        baseResponse.setMessage("permissions updated");
        baseResponse.setSuccess(true);
        baseResponse.setStatusCode(String.valueOf(HttpStatus.OK.value()));
        return baseResponse;
    }

    @Override
    public List<BaseResponse> detachPermissionFromRole(List<DetachPermissionRequest> detachPermissionRequestList) {

        List<BaseResponse> successBaseResponses = new ArrayList<>();

        for (DetachPermissionRequest detachPermissionRequest : detachPermissionRequestList) {
            try {
                BaseResponse baseResponse = new BaseResponse();
                Modules modules = moduleRepository.findByModuleName(detachPermissionRequest.getModule());
                if (modules == null) {
                    throw new PermissionServiceException(NO_MODULE_FOUND.label + detachPermissionRequest.getModule() + MODULE_NAME.label, HttpStatus.NOT_FOUND);
                }
                String moduleId = modules.getId();

                SubModules subModules = subModuleRepository.findBySubModuleName(detachPermissionRequest.getSubModule());
                if (subModules == null) {
                    throw new PermissionServiceException(NO_SUBMODULE_FOUND + detachPermissionRequest.getSubModule() + SUBMODULE_NAME.label, HttpStatus.NOT_FOUND);
                }
                String subModuleId = subModules.getId();

                Permissions permissions = permissionsRepository.findByPermissionTitleAndModuleIdAndSubModuleId(detachPermissionRequest.getPermissionTitle(), moduleId, subModuleId);
                if (permissions == null) {
                    throw new PermissionServiceException(NO_PERMISSION_FOUND.label + detachPermissionRequest.getPermissionTitle() + PERMISSION_TITLE.label + moduleId + MODUELID.label + subModuleId + SUBMODULEID.label, HttpStatus.NOT_FOUND);
                }
                String permissionId = permissions.getId();

                if(Objects.isNull(detachPermissionRequest.getModified())){

                    Role role = roleRepository.findByRoleName(detachPermissionRequest.getRoleName());
                    if (role == null) {
                        throw new PermissionServiceException("No role found with this " + detachPermissionRequest.getPermissionTitle() + " roleName.", HttpStatus.NOT_FOUND);
                    }

                    List<String> permissionIdList = role.getPermissionIdList();
                    permissionIdList.remove(permissionId);

                    role.setPermissionIdList(permissionIdList);
                    roleRepository.save(role);

                    baseResponse.setPayload(detachPermissionRequest);
                    baseResponse.setMessage("Successfully detached the permission from the role.");
                    baseResponse.setSuccess(true);
                    successBaseResponses.add(baseResponse);
                }else{
                    //Update the permissions
                    updatePermissions(permissions, detachPermissionRequest.getModified(),successBaseResponses);
                }

            } catch (PermissionServiceException permissionServiceException) {
                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage(permissionServiceException.getMessage());
                baseResponse.setStatusCode(String.valueOf(permissionServiceException.getHttpStatus()));
                baseResponse.setPayload(detachPermissionRequest);
                baseResponse.setSuccess(false);
                successBaseResponses.add(baseResponse);
            }
        }
        return successBaseResponses;
    }

    public void updatePermissions(Permissions oldPermission, PermissionsRequest newPermission,List<BaseResponse> successBaseResponses){
        BaseResponse baseResponse = new BaseResponse();
        if(!Objects.isNull(newPermission.getPermissionTitle())){
            oldPermission.setPermissionTitle(newPermission.getPermissionTitle());
        }
        if(!Objects.isNull(newPermission.getSubModule())){
            SubModules subModules = subModuleRepository.findBySubModuleName(newPermission.getSubModule());
            if (subModules == null) {
                throw new PermissionServiceException(NO_SUBMODULE_FOUND.label + newPermission.getSubModule() + SUBMODULE_NAME.label, HttpStatus.NOT_FOUND);
            }
            String subModuleId = subModules.getId();
            oldPermission.setSubModuleId(subModuleId);
        }
        if(!Objects.isNull(newPermission.getModule())){
            Modules modules = moduleRepository.findByModuleName(newPermission.getModule());
            if (modules == null) {
                throw new PermissionServiceException(NO_MODULE_FOUND.label + newPermission.getModule() + MODULE_NAME.label, HttpStatus.NOT_FOUND);
            }
            String moduleId = modules.getId();
            oldPermission.setModuleId(moduleId);
        }
        if(!Objects.isNull(newPermission.getDescription())){
            oldPermission.setDescription(newPermission.getDescription());
        }
        if(!Objects.isNull(newPermission.getScreen())){
            oldPermission.setDescription(newPermission.getScreen());
        }

        //check modified permissions already exist or not
        Permissions permissions = permissionsRepository.findByPermissionTitleAndModuleIdAndSubModuleId(oldPermission.getPermissionTitle(), oldPermission.getModuleId(), oldPermission.getSubModuleId());
        if(permissions != null){
            throw new PermissionServiceException("Modified permission already exist.", HttpStatus.BAD_REQUEST);
        }
        permissionsRepository.save(oldPermission);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("Successfully modified permissions.");
        baseResponse.setPayload(oldPermission);
        baseResponse.setStatusCode(HttpStatus.OK.toString());
        successBaseResponses.add(baseResponse);
    }

    @Override
    public List<BaseResponse> detachApiFromPermission(List<DetachApiRequest> detachApiRequestList) {

        List<BaseResponse> successBaseResponses = new ArrayList<>();

        for (DetachApiRequest detachApiRequest : detachApiRequestList) {
            try {

                BaseResponse baseResponse = new BaseResponse();

                Modules modules = moduleRepository.findByModuleName(detachApiRequest.getModule());
                if (modules == null) {
                    throw new PermissionServiceException(NO_MODULE_FOUND.label + detachApiRequest.getModule() + MODULE_NAME.label, HttpStatus.NOT_FOUND);
                }
                String moduleId = modules.getId();

                SubModules subModules = subModuleRepository.findBySubModuleName(detachApiRequest.getSubModule());
                if (subModules == null) {
                    throw new PermissionServiceException(NO_SUBMODULE_FOUND.label + detachApiRequest.getSubModule() + SUBMODULE_NAME.label, HttpStatus.NOT_FOUND);
                }
                String subModuleId = subModules.getId();

                Permissions permissions = permissionsRepository.findByPermissionTitleAndModuleIdAndSubModuleId(detachApiRequest.getPermissionTitle(), moduleId, subModuleId);
                if (permissions == null) {
                    throw new PermissionServiceException("No permission found with this " + detachApiRequest.getPermissionTitle() + " permissionTitle, " + moduleId + " moduleId and " + subModuleId + " subModuleId.", HttpStatus.NOT_FOUND);
                }

                List<String> allowedEndpointIdList = permissions.getAllowedEndpointIdList();

                PlatformApiDetails platformApiDetails = platformApiDetailsRepository.findIdByApiRouteAndApiMethod(detachApiRequest.getApiRoute(), detachApiRequest.getApiMethod());

                if (platformApiDetails == null) {
                    throw new PermissionServiceException(NO_PLATFORM_API_DETAILS_FOUND.label + detachApiRequest.getApiRoute() + API_ROUTE.label + detachApiRequest.getApiMethod() + APIMETHOD.label, HttpStatus.NOT_FOUND);
                }

                String apiId = platformApiDetails.getId();

                allowedEndpointIdList.remove(apiId);
                permissions.setAllowedEndpointIdList(allowedEndpointIdList);

                permissionsRepository.save(permissions);

                baseResponse.setMessage("Successfully detached platformApiDetails from the permission.");
                baseResponse.setSuccess(true);
                baseResponse.setStatusCode(String.valueOf(HttpStatus.OK.value()));
                baseResponse.setPayload(detachApiRequest);
                successBaseResponses.add(baseResponse);
            } catch (PermissionServiceException permissionServiceException) {
                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage(permissionServiceException.getMessage());
                baseResponse.setStatusCode(String.valueOf(permissionServiceException.getHttpStatus()));
                baseResponse.setPayload(detachApiRequest);
                baseResponse.setSuccess(false);
                successBaseResponses.add(baseResponse);
            }
        }

        return successBaseResponses;
    }

    @Override
    public List<BaseResponse> detachApiFromAllPermissionsOrUpdateApi(List<RemoveOrUpdatePlatformApiDetailsDto> removeOrUpdatePlatformApiDetailsDtoList) {

        List<BaseResponse> successBaseResponses = new ArrayList<>();

        for (RemoveOrUpdatePlatformApiDetailsDto removeOrUpdatePlatformApiDetailsDto : removeOrUpdatePlatformApiDetailsDtoList) {
            try {

                BaseResponse baseResponse = new BaseResponse();

                PlatformApiDetails platformApiDetails = platformApiDetailsRepository.findIdByApiRouteAndApiMethod(removeOrUpdatePlatformApiDetailsDto.getApiRoute(), removeOrUpdatePlatformApiDetailsDto.getApiMethod());

                if (platformApiDetails == null) {
                    throw new PermissionServiceException("No platformApiDetails found with this " + removeOrUpdatePlatformApiDetailsDto.getApiRoute() + " apiRoute and " + removeOrUpdatePlatformApiDetailsDto.getApiMethod() + " apiMethod.", HttpStatus.NOT_FOUND);
                }

                if (Objects.isNull(removeOrUpdatePlatformApiDetailsDto.getModified())) {
                    //code for removing this platformApiDetailsId from all permissions

                    List<Permissions> modifiedPermissions = permissionsRepository.removeEndpointIds(platformApiDetails.getId());
                    permissionsRepository.saveAll(modifiedPermissions);

                    baseResponse.setMessage("Successfully detached platformApiDetails from the all permissions.");
                    baseResponse.setSuccess(true);
                    baseResponse.setPayload(removeOrUpdatePlatformApiDetailsDto);
                    baseResponse.setStatusCode(String.valueOf(HttpStatus.OK.value()));

                } else {
                    //code for updating platformApiDetails

                    updatePlatformApiDetails(removeOrUpdatePlatformApiDetailsDto,platformApiDetails);
                    baseResponse.setMessage("Successfully updated PlatformApiDetails.");
                    baseResponse.setSuccess(true);
                    baseResponse.setPayload(removeOrUpdatePlatformApiDetailsDto);
                    baseResponse.setStatusCode(String.valueOf(HttpStatus.OK.value()));
                }
                successBaseResponses.add(baseResponse);
            } catch (PermissionServiceException permissionServiceException) {
                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage(permissionServiceException.getMessage());
                baseResponse.setStatusCode(String.valueOf(permissionServiceException.getHttpStatus()));
                baseResponse.setPayload(removeOrUpdatePlatformApiDetailsDto);
                baseResponse.setSuccess(false);
                successBaseResponses.add(baseResponse);
            }
        }

        return successBaseResponses;
    }

    public void updatePlatformApiDetails(RemoveOrUpdatePlatformApiDetailsDto removeOrUpdatePlatformApiDetailsDto,PlatformApiDetails platformApiDetails){
        if (!Objects.isNull(removeOrUpdatePlatformApiDetailsDto.getModified().getApiRoute())) {
            platformApiDetails.setApiRoute(removeOrUpdatePlatformApiDetailsDto.getModified().getApiRoute());
        }
        if (!Objects.isNull(removeOrUpdatePlatformApiDetailsDto.getModified().getApiMethod())) {
            platformApiDetails.setApiMethod(removeOrUpdatePlatformApiDetailsDto.getModified().getApiMethod());
        }
        if (!Objects.isNull(removeOrUpdatePlatformApiDetailsDto.getModified().getApiDescription())) {
            platformApiDetails.setApiDescription(removeOrUpdatePlatformApiDetailsDto.getModified().getApiDescription());
        }
        platformApiDetailsRepository.save(platformApiDetails);
    }

    @Override
    public BaseResponse renameSubModule(RenameSubModuleRequest renameSubModuleRequest){
        BaseResponse baseResponse = new BaseResponse();
        Modules modules = moduleRepository.findByModuleName(renameSubModuleRequest.getModuleName());
        if (modules==null) {
            throw new PermissionServiceException(NO_MODULE_FOUND.label + renameSubModuleRequest.getModuleName() + MODULE_NAME.label, HttpStatus.NOT_FOUND);
        }

        SubModules subModules = subModuleRepository.findBySubModuleNameAndModuleId(renameSubModuleRequest.getSubModuleName(), modules.getId());
        if (subModules==null) {
            throw new PermissionServiceException(NO_SUBMODULE_FOUND.label + renameSubModuleRequest.getSubModuleName() + SUBMODULE_NAME, HttpStatus.NOT_FOUND);
        }

        if(!Objects.isNull(renameSubModuleRequest.getModifiedSubModuleName())){
            subModules.setSubModuleName(renameSubModuleRequest.getModifiedSubModuleName());
        }

        if(!Objects.isNull(renameSubModuleRequest.getModifiedModuleName())){
            Modules modifiedModules = moduleRepository.findByModuleName(renameSubModuleRequest.getModifiedModuleName());
            if (modifiedModules==null) {
                throw new PermissionServiceException(NO_MODULE_FOUND.label + renameSubModuleRequest.getModifiedModuleName() + " moduleName.", HttpStatus.NOT_FOUND);
            }
            subModules.setModuleId(modifiedModules.getId());
        }
        subModuleRepository.save(subModules);
        baseResponse.setPayload(subModules);
        baseResponse.setSuccess(true);
        baseResponse.setMessage("Successfully updated the subModule.");
        return baseResponse;
    }

    @Override
    public List<BaseResponse> deleteSubModule(List<DeleteSubModuleRequest> deleteSubModuleRequestList) {
        List<BaseResponse> successBaseResponses = new ArrayList<>();

        for (DeleteSubModuleRequest deleteSubModuleRequest : deleteSubModuleRequestList) {
            try {
                Modules modules = moduleRepository.findByModuleName(deleteSubModuleRequest.getModuleName());
                if (modules==null) {
                    throw new PermissionServiceException(NO_MODULE_FOUND.label + deleteSubModuleRequest.getModuleName() + MODULE_NAME.label, HttpStatus.NOT_FOUND);
                }

                SubModules subModules = subModuleRepository.findBySubModuleNameAndModuleId(deleteSubModuleRequest.getSubModuleName(), modules.getId());
                if (subModules==null) {
                    throw new PermissionServiceException(NO_SUBMODULE_FOUND.label + deleteSubModuleRequest.getSubModuleName() + SUBMODULE_NAME.label, HttpStatus.NOT_FOUND);
                }

                subModuleRepository.deleteById(subModules.getId());
                detachSubModuleFromPermissions(subModules);

                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage("SubModule successfully deleted.");
                baseResponse.setPayload(deleteSubModuleRequest);
                baseResponse.setSuccess(true);
                baseResponse.setStatusCode(HttpStatus.OK.toString());
                successBaseResponses.add(baseResponse);
            } catch (PermissionServiceException permissionServiceException) {
                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage(permissionServiceException.getMessage());
                baseResponse.setStatusCode(String.valueOf(permissionServiceException.getHttpStatus()));
                baseResponse.setPayload(deleteSubModuleRequest);
                baseResponse.setSuccess(false);
                successBaseResponses.add(baseResponse);
            }
        }
        return successBaseResponses;
    }

    public void detachSubModuleFromPermissions(SubModules subModules) {

        List<Permissions> permissions = permissionsRepository.findBySubModuleId(subModules.getId());
        for (Permissions permission : permissions) {
            permission.setSubModuleId(null);
            permissionsRepository.save(permission);
        }
    }

    @Override
    public List<BaseResponse> deleteModule(List<String> deleteModuleRequestList){
        List<BaseResponse> successBaseResponses = new ArrayList<>();

        for (String moduleName : deleteModuleRequestList) {
            try {
                Modules modules = moduleRepository.findByModuleName(moduleName);
                if (modules==null) {
                    throw new PermissionServiceException(NO_MODULE_FOUND.label + deleteModuleRequestList + MODULE_NAME.label, HttpStatus.NOT_FOUND);
                }

                moduleRepository.deleteById(modules.getId());

                List<SubModules> subModules = subModuleRepository.findByModuleId(modules.getId());
                subModuleRepository.deleteAll(subModules);

                detachModuleAndSubModuleFromPermissions(modules,subModules);

                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage("Module successfully deleted and detached from sub module and permissions.");
                baseResponse.setPayload(moduleName);
                baseResponse.setSuccess(true);
                baseResponse.setStatusCode(HttpStatus.OK.toString());
                successBaseResponses.add(baseResponse);
            } catch (PermissionServiceException permissionServiceException) {
                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage(permissionServiceException.getMessage());
                baseResponse.setStatusCode(String.valueOf(permissionServiceException.getHttpStatus()));
                baseResponse.setPayload(moduleName);
                baseResponse.setSuccess(false);
                successBaseResponses.add(baseResponse);
            }
        }
        return successBaseResponses;
    }

    public void detachModuleAndSubModuleFromPermissions(Modules modules ,List<SubModules> subModules){
        for(SubModules subModule :subModules){
            List<Permissions> permissions = permissionsRepository.findByModuleIdAndSubModuleId(modules.getId(),subModule.getId());
            List<Permissions> permissionsWithOnlyModuleId =  permissionsRepository.findByModuleId(modules.getId());
            for(Permissions permission :permissions){
                permission.setModuleId(null);
                permission.setSubModuleId(null);
                permissionsRepository.save(permission);
            }
            for(Permissions permission :permissionsWithOnlyModuleId){
                permission.setModuleId(null);
                permission.setSubModuleId(null);
                permissionsRepository.save(permission);
            }
        }

    }

    @Override
    public List<BaseResponse> deleteRole(List<String> deleteRoleRequestList){
        List<BaseResponse> successBaseResponses = new ArrayList<>();

        for (String roleName : deleteRoleRequestList) {
            try {
                Role role = roleRepository.findByRoleName(roleName);
                if (role==null) {
                    throw new PermissionServiceException(NO_ROLE_FOUND.label + roleName + ROLE_NAME.label, HttpStatus.NOT_FOUND);
                }

                roleRepository.deleteById(role.getId());

                detachRoleFromUserOrgRole(role.getId());

                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage("Role successfully deleted and detached from UserOrgRole.");
                baseResponse.setPayload(roleName);
                baseResponse.setSuccess(true);
                baseResponse.setStatusCode(HttpStatus.OK.toString());
                successBaseResponses.add(baseResponse);
            } catch (PermissionServiceException permissionServiceException) {
                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage(permissionServiceException.getMessage());
                baseResponse.setStatusCode(String.valueOf(permissionServiceException.getHttpStatus()));
                baseResponse.setPayload(roleName);
                baseResponse.setSuccess(false);
                successBaseResponses.add(baseResponse);
            }
        }
        return successBaseResponses;
    }

    public void detachRoleFromUserOrgRole(String deletedRoleId){
        List<OrganizationRole> orgRoles = orgRoleRepository.findByRoleId(deletedRoleId);
        orgRoleRepository.deleteAll(orgRoles);
        List<String> deletedOrgRoleIds = new ArrayList<>();
        orgRoles.forEach(orgRole -> deletedOrgRoleIds.add(orgRole.getId()));

        List<ProjectOrgRole> projectOrgRoles = projectOrgRoleRepository.findByRoleId(deletedRoleId);
        projectOrgRoleRepository.deleteAll(projectOrgRoles);
        List<String> deletedProjectRoleIds = new ArrayList<>();
        projectOrgRoles.forEach(projectOrgRole -> deletedProjectRoleIds.add(projectOrgRole.getId()));

        List<String> deletedRoles = new ArrayList<>();
        deletedRoles.add(deletedRoleId);

        List<UserOrgRole> userOrgRoles = userOrgRoleRepository.
                removeOrganizationRoleIdsAndPlatformRoleIdListAndProjectOrgRoleIdList(
                        deletedOrgRoleIds,
                        deletedRoles,
                        deletedProjectRoleIds
                );

        userOrgRoleRepository.saveAll(userOrgRoles);

    }

    @Override
    public List<BaseResponse> deletePermission(List<DeletePermissionRequest> deletePermissionsRequestList){
        List<BaseResponse> successBaseResponses = new ArrayList<>();

        for (DeletePermissionRequest DeletePermissionRequest : deletePermissionsRequestList) {
            try {
                Modules modules = moduleRepository.findByModuleName(DeletePermissionRequest.getModule());
                if (modules == null) {
                    throw new PermissionServiceException(NO_MODULE_FOUND.label + DeletePermissionRequest.getModule() + MODULE_NAME.label, HttpStatus.NOT_FOUND);
                }
                String moduleId = modules.getId();

                SubModules subModules = subModuleRepository.findBySubModuleName(DeletePermissionRequest.getSubModule());
                if (subModules == null) {
                    throw new PermissionServiceException(NO_SUBMODULE_FOUND.label + DeletePermissionRequest.getSubModule() + SUBMODULE_NAME.label, HttpStatus.NOT_FOUND);
                }
                String subModuleId = subModules.getId();

                Permissions permissions = permissionsRepository.findByPermissionTitleAndModuleIdAndSubModuleId(DeletePermissionRequest.getPermissionTitle(), moduleId, subModuleId);
                if (permissions == null) {
                    throw new PermissionServiceException("No permission found with this " + DeletePermissionRequest.getPermissionTitle() + " permissionTitle, " + moduleId + " moduleId and " + subModuleId + " subModuleId.", HttpStatus.NOT_FOUND);
                }

                permissionsRepository.deleteById(permissions.getId());

                detachPermissionFromRoles(permissions.getId());

                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage("Permission successfully deleted and detached from roles.");
                baseResponse.setPayload(DeletePermissionRequest);
                baseResponse.setSuccess(true);
                baseResponse.setStatusCode(HttpStatus.OK.toString());
                successBaseResponses.add(baseResponse);
            } catch (PermissionServiceException permissionServiceException) {
                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage(permissionServiceException.getMessage());
                baseResponse.setStatusCode(String.valueOf(permissionServiceException.getHttpStatus()));
                baseResponse.setPayload(DeletePermissionRequest);
                baseResponse.setSuccess(false);
                successBaseResponses.add(baseResponse);
            }
        }
        return successBaseResponses;
    }

    public void detachPermissionFromRoles(String permissionId){
        List<String> deletedPermissions = new ArrayList<>();
        deletedPermissions.add(permissionId);
        List<Role> roles = roleRepository.removePermissionsIds(deletedPermissions);
        roleRepository.saveAll(roles);
    }

    @Override
    public List<BaseResponse> deletePlatformApiDetails(List<DeletePlatformApiDetailsRequest> deletePlatformApiDetailsRequestList){
        List<BaseResponse> successBaseResponses = new ArrayList<>();

        for (DeletePlatformApiDetailsRequest deletePlatformApiDetailsRequest : deletePlatformApiDetailsRequestList) {
            try {
                PlatformApiDetails platformApiDetails = platformApiDetailsRepository.findIdByApiRouteAndApiMethod(deletePlatformApiDetailsRequest.getApiRoute(), deletePlatformApiDetailsRequest.getApiMethod());

                if (platformApiDetails == null) {
                    throw new PermissionServiceException("No platformApiDetails found with this " + deletePlatformApiDetailsRequest.getApiRoute() + " apiRoute and " + deletePlatformApiDetailsRequest.getApiMethod() + " apiMethod.", HttpStatus.NOT_FOUND);
                }

                platformApiDetailsRepository.deleteById(platformApiDetails.getId());

                List<Permissions> modifiedPermissions = permissionsRepository.removeEndpointIds(platformApiDetails.getId());
                permissionsRepository.saveAll(modifiedPermissions);

                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage("PlatformApiDetails successfully deleted and detached from permissions.");
                baseResponse.setPayload(deletePlatformApiDetailsRequest);
                baseResponse.setSuccess(true);
                baseResponse.setStatusCode(HttpStatus.OK.toString());
                successBaseResponses.add(baseResponse);
            } catch (PermissionServiceException permissionServiceException) {
                BaseResponse baseResponse = new BaseResponse();
                baseResponse.setMessage(permissionServiceException.getMessage());
                baseResponse.setStatusCode(String.valueOf(permissionServiceException.getHttpStatus()));
                baseResponse.setPayload(deletePlatformApiDetailsRequest);
                baseResponse.setSuccess(false);
                successBaseResponses.add(baseResponse);
            }
        }
        return successBaseResponses;
    }

}
