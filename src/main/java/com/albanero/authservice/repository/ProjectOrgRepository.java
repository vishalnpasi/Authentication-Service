package com.albanero.authservice.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.ProjectOrg;

@Repository
public interface ProjectOrgRepository extends MongoRepository<ProjectOrg, String> {
	public List<ProjectOrg> findByIdAndOrgId(String id, String orgId);

	public List<ProjectOrg> findByOrgId(String orgId);
	
	public ProjectOrg findByProjectIdAndOrgId(String projectId, String orgId);
	
	public ProjectOrg findByProjectId(String projectId);
	
}

