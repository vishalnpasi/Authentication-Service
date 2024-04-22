package com.albanero.authservice.service;

import com.albanero.authservice.common.dto.request.AddMembersRequest;
import com.albanero.authservice.common.dto.request.AddRemoveMemberRequest;
import com.albanero.authservice.common.dto.request.ProjectLevelDetails;
import com.albanero.authservice.common.dto.response.BaseResponse;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

@Service
public interface ProjectService {

    public BaseResponse createOrgProject(HttpServletRequest request, ProjectLevelDetails projectDetails);

    public BaseResponse fetchProjectDefaultRoles(Optional<String> projectId, Optional<String> orgId, Integer page, Integer pageSize);

    public BaseResponse addProjectMember(HttpServletRequest request, AddMembersRequest addMemberRequest);

    public BaseResponse verifyOrgProject(HttpServletRequest request, ProjectLevelDetails projectDetails);

    public BaseResponse fetchListOfProjects(HttpServletRequest request, String orgId);

    public BaseResponse fetchListOfUsersInProject(HttpServletRequest request, ProjectLevelDetails projectLevelDetails);

    public BaseResponse removeProjectMember(HttpServletRequest request, AddRemoveMemberRequest removeMemberRequest);

    public BaseResponse fetchUserProjects(HttpServletRequest request);

    public BaseResponse setUserDefaultProject(HttpServletRequest request, String orgId, String projectId);

    public BaseResponse fetchUserDefaultProject(HttpServletRequest httpServletRequest, String orgId);

    public BaseResponse removeUserDefaultProject(HttpServletRequest httpServletRequest, String orgId);
}
