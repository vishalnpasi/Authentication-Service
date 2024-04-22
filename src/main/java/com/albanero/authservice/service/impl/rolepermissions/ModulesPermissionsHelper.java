package com.albanero.authservice.service.impl.rolepermissions;

import com.albanero.authservice.common.constants.PermissionConstants;
import com.albanero.authservice.common.dto.ProjectOrgRoleId;
import com.albanero.authservice.common.dto.request.OrgLevelDetails;
import com.albanero.authservice.common.dto.response.ModuleNameDto;
import com.albanero.authservice.common.util.HelperUtil;
import com.albanero.authservice.exception.UserRoleServiceException;
import com.albanero.authservice.model.*;
import com.albanero.authservice.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.*;

import static com.albanero.authservice.common.constants.ExceptionMessagesConstants.ACTION_FAILED_EXCEPTION;
import static com.albanero.authservice.common.constants.LoggerConstants.AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO;

@Service
public class ModulesPermissionsHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(ModulesPermissionsHelper.class);

    private static final String MODULES_PERMISSIONS_HELPER = "ModulesPermissionsHelper";

    private final ModuleRepository moduleRepository;

    private final PermissionsRepository permissionsRepository;

    private final PermissionsRepository permissionsRepo;

    private final SubModuleRepository subModuleRepository;

    private final HelperUtil helperUtil;

    private final OrgRepository orgRepository;

    private final ProjectRepository projectRepository;

    private final ProjectOrgRepository projectOrgRepository;

    private final ProjectOrgRoleRepository projectOrgRoleRepository;

    private final UserOrgRoleRepository userOrgRoleRepository;

    @Autowired
    public ModulesPermissionsHelper(ModuleRepository moduleRepository, PermissionsRepository permissionsRepository, PermissionsRepository permissionsRepo, SubModuleRepository subModuleRepository, HelperUtil helperUtil, OrgRepository orgRepository, ProjectRepository projectRepository, ProjectOrgRepository projectOrgRepository, ProjectOrgRoleRepository projectOrgRoleRepository, UserOrgRoleRepository userOrgRoleRepository) {
        this.moduleRepository = moduleRepository;
        this.permissionsRepository = permissionsRepository;
        this.permissionsRepo = permissionsRepo;
        this.subModuleRepository = subModuleRepository;
        this.helperUtil = helperUtil;
        this.orgRepository = orgRepository;
        this.projectRepository = projectRepository;
        this.projectOrgRepository = projectOrgRepository;
        this.projectOrgRoleRepository = projectOrgRoleRepository;
        this.userOrgRoleRepository = userOrgRoleRepository;
    }

    public List<String> getPermissionIdList(List<ModuleNameDto> permissionTree) {
        List<String> permissionIdList = new ArrayList<>();
        for(ModuleNameDto modules: permissionTree) {
            List<ModuleNameDto> subModules = modules.getSub();
            for(ModuleNameDto subModule : subModules) {
                if(Objects.isNull(subModule.getSub()) && Boolean.TRUE.equals(subModule.getIsSelected())) {
                    permissionIdList.add(subModule.getId());
                } else generatePermissionListBasedOnSubMod(subModule, permissionIdList);
            }
        }
        return permissionIdList;
    }

    private static void generatePermissionListBasedOnSubMod(ModuleNameDto subModule, List<String> permissionIdList) {
        List<ModuleNameDto> permissions = subModule.getSub();
        for(ModuleNameDto permission : permissions) {
            if(Objects.isNull(permission.getSub()) && Boolean.TRUE.equals(permission.getIsSelected())) {
                permissionIdList.add(permission.getId());
            }
        }
    }

    public List<String> getDefaultPermissionId(String roleType) {
        List<String> defaultPermissionId ;
        SubModules subModules = new SubModules();
        if(roleType.equals(PermissionConstants.PROJECT_CUSTOM)) {
            subModules = subModuleRepository.findBySubModuleName(PermissionConstants.USER_DEFAULT);
        } else if(roleType.equals(PermissionConstants.ORGANIZATION_CUSTOM)) {
            subModules = subModuleRepository.findBySubModuleName(PermissionConstants.USER_SETTINGS);
        }
        defaultPermissionId = permissionsRepo.findBySubModuleId(subModules.getId()).stream().map(Permissions::getId).toList();
        return defaultPermissionId;
    }

    public Set<String> getModuleFromRole(Role role) {
        Set<String> modulesHashSet = new HashSet<>();
        List<String> permissionIdList = role.getPermissionIdList();
        for (String permissionId : permissionIdList) {
            Optional<Permissions> permission = permissionsRepo.findById(permissionId);
            if (permission.isPresent() && permission.get().getModuleId() != null) {
                Optional<Modules> modules = moduleRepository.findById(permission.get().getModuleId());
                if (modules.isPresent()) {
                    modulesHashSet.add(modules.get().getId());
                }else{
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,MODULES_PERMISSIONS_HELPER,"getModuleFromRole","Module not found with this moduleId",permission.get().getModuleId());
                    throw new UserRoleServiceException(String.valueOf(ACTION_FAILED_EXCEPTION), HttpStatus.INTERNAL_SERVER_ERROR);
                }
            }else{
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,MODULES_PERMISSIONS_HELPER,"getModuleFromRole","Permission not found with this permissionId",permissionId);
            }
        }
        return modulesHashSet;
    }

    public Set<String> getSubModulesFromRole(Role role) {
        Set<String> subModulesHashSet = new HashSet<>();
        List<String> permissionIdList = role.getPermissionIdList();
        for (String permissionId : permissionIdList) {
            Optional<Permissions> permissionsOptional = permissionsRepository.findById(permissionId);
            if (permissionsOptional.isPresent()) {
                Permissions permission = permissionsOptional.get();
                if (permission.getSubModuleId() != null) {
                    Optional<SubModules> subModules = subModuleRepository.findById(permission.getSubModuleId());
                    if (Boolean.TRUE.equals(subModules.isPresent())) {
                        subModulesHashSet.add(subModules.get().getId());
                    }
                }
            }
        }
        return subModulesHashSet;
    }

    public List<ModuleNameDto> permissionTreeFromModules(Set<String> moduleIdList, Set<String> submoduleIdList, List<String> permissionIdsList, Boolean isAdmin) {
        List<ModuleNameDto> permissionTree = new ArrayList<>();
        List<Modules> allModules = moduleRepository.findAll();
        Boolean isSelected = false;
        for (Modules module : allModules) {
            isSelected = helperUtil.checkIfAdminOrHasPermissionModuleOrSubModule(moduleIdList, module.getId(), isAdmin);
            ModuleNameDto moduleNameDto = helperUtil.setModuleNameDtoFromModule(module, isSelected);

            List<SubModules> subModulesList = subModuleRepository.findByModuleId(module.getId());
            if (subModulesList.isEmpty()) {
                List<ModuleNameDto> moduleNamePermissions = new ArrayList<>();
                List<Permissions> permissions = permissionsRepository.findByModuleId(module.getId());
                for (Permissions permission : permissions) {
                    isSelected =  helperUtil.checkIfAdminOrHasListPermission(permissionIdsList, permission.getId(), isAdmin);
                    ModuleNameDto moduleNamePermission = helperUtil.setModuleNameDtoFromPermissions(permission, isSelected);
                    moduleNamePermissions.add(moduleNamePermission);
                }
                moduleNameDto.setSub(moduleNamePermissions);
            } else {
                List<ModuleNameDto> moduleNameSubModules = new ArrayList<>();
                for (SubModules subModule : subModulesList) {
                    isSelected =  helperUtil.checkIfAdminOrHasPermissionModuleOrSubModule(submoduleIdList, subModule.getId(), isAdmin);
                    ModuleNameDto moduleNameSubModule = helperUtil.setModuleNameDtoFromSubmodules(subModule, isSelected);

                    List<Permissions> permissions = permissionsRepository.findBySubModuleId(subModule.getId());
                    List<ModuleNameDto> moduleNamePermissions = new ArrayList<>();
                    for (Permissions permission : permissions) {
                        isSelected =  helperUtil.checkIfAdminOrHasListPermission(permissionIdsList, permission.getId(), isAdmin);
                        ModuleNameDto moduleNamePermission = helperUtil.setModuleNameDtoFromPermissions(permission, isSelected);
                        moduleNamePermissions.add(moduleNamePermission);
                    }
                    moduleNameSubModule.setSub(moduleNamePermissions);
                    moduleNameSubModules.add(moduleNameSubModule);
                }
                moduleNameDto.setSub(moduleNameSubModules);
            }
            permissionTree.add(moduleNameDto);
        }
        return permissionTree;
    }

    public List<OrgLevelDetails> getOrganzationProject(List<String> orgIds, List<String> projectIds) {
        List<OrgLevelDetails> orgLevelDetailsList = new ArrayList<>();
        for(String orgId : orgIds) {
            OrgLevelDetails orgLevelDetails = new OrgLevelDetails();
            Optional<Organization> org = orgRepository.findById(orgId);
            if(org.isEmpty()){
                LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,MODULES_PERMISSIONS_HELPER,"getOrganzationProject","Organization not found with this organizationId",orgId);
                throw new UserRoleServiceException(String.valueOf(ACTION_FAILED_EXCEPTION), HttpStatus.INTERNAL_SERVER_ERROR);
            }
            orgLevelDetails.setOrgId(orgId);
            orgLevelDetails.setOrgName(org.get().getName());
            List<Project> matchedProject = new ArrayList<>();
            for(String projectId: projectIds) {
                Optional<Project> project = projectRepository.findById(projectId);
                if(project.isEmpty()){
                    LOGGER.error(AUTHENTICATION_SERVICE_ERROR_LOG_TAG_WITH_INFO,MODULES_PERMISSIONS_HELPER,"getOrganzationProject","Project not found with this projectId",projectId);
                    throw new UserRoleServiceException(String.valueOf(ACTION_FAILED_EXCEPTION), HttpStatus.INTERNAL_SERVER_ERROR);
                }
                if(!Objects.isNull(projectOrgRepository.findByProjectIdAndOrgId(projectId, orgId))) {
                    matchedProject.add(project.get());
                }
            }
            orgLevelDetails.setProjectDetails(matchedProject);
            orgLevelDetailsList.add(orgLevelDetails);
        }
        return orgLevelDetailsList;
    }

    public void removeRolesFromProjectAndUsers(List<String> projectId, Role role) {
        List<String> existingProjectId = role.getRoleType().getProjectId();
        List<String> removedProjectIds = existingProjectId.stream()
                .filter(aObject -> ! projectId.contains(aObject))
                .toList();

        for(String removedProjectId : removedProjectIds) {
            ProjectOrg projectOrg = projectOrgRepository.findByProjectId(removedProjectId);
            ProjectOrgRole projectOrgRole = projectOrgRoleRepository.findByProjectOrgIdAndRoleId(projectOrg.getId(), role.getId());

            if(!Objects.isNull(projectOrgRole)) {
                List<UserOrgRole> userOrgRoleList = userOrgRoleRepository.findByProjectOrgRoleIdListIn(Collections.singletonList(projectOrgRole.getId()));
                for(UserOrgRole userOrgRole: userOrgRoleList) {
                    List<ProjectOrgRoleId> updatedProjectOrgRoleIdList = new ArrayList<>();
                    userOrgRole.getProjectOrgRoleIdList().forEach(projectOrgRoleId -> {
                        if(!projectOrgRoleId.getProjectOrganizationRoleId().equals(projectOrgRole.getId())){
                            updatedProjectOrgRoleIdList.add(projectOrgRoleId);
                        }
                    });
                    userOrgRole.setProjectOrgRoleIdList(updatedProjectOrgRoleIdList);
                    userOrgRoleRepository.save(userOrgRole);
                }
                projectOrgRoleRepository.delete(projectOrgRole);
            }
        }
    }
}
