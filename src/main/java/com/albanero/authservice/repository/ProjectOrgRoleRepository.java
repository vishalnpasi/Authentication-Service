package com.albanero.authservice.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.ProjectOrgRole;

@Repository
public interface ProjectOrgRoleRepository extends MongoRepository<ProjectOrgRole, String> {
	public ProjectOrgRole findByProjectOrgIdAndRoleId(String projectOrgId, String roleId);
	public List<ProjectOrgRole> findByRoleId(String roleId);
	public List<ProjectOrgRole> findByProjectOrgId(String projectOrgId);
}
