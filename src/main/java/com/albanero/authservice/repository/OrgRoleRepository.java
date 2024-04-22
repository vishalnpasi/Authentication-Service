package com.albanero.authservice.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.OrganizationRole;

@Repository
public interface OrgRoleRepository extends MongoRepository<OrganizationRole, String> {
	@Query("{'id':?0}")
	public OrganizationRole findByPrimaryId(String id);
	public List<OrganizationRole> findByOrgId(String orgId);
	public List<OrganizationRole> findByRoleId(String roleId);
	public OrganizationRole findByOrgIdAndRoleId(String orgId, String roleId);
	public OrganizationRole findByIdAndOrgId(String id, String orgId);
}
