package com.albanero.authservice.repository;

import com.albanero.authservice.common.constants.PermissionConstants;
import org.springframework.data.mongodb.repository.Aggregation;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.Role;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends MongoRepository<Role, String> {
	public Role findByRoleName(String role);

	public List<String> getPermissionListByRoleName(String role);

	@Query("{'roleType.roleType':'"+ PermissionConstants.PROJECT_DEFAULT +"'}")
	public List<Role> findByProjectDefaultRoleType();

	@Query("{'roleType.projectId': ?0 }")
	public List<Role> findByProjectId(Optional<String> projectId);

	@Query("{'roleType.roleType':'"+ PermissionConstants.ORGANIZATION_DEFAULT +"'}")
	public List<Role> findByOrganizationDefaultRoleType();

	@Query("{'roleType.orgId': ?0 }")
	public List<Role> findByOrgId(Optional<String> orgId);

	@Query("{$and: [ {'roleType.orgId': ?0}, {'roleType.roleType':'"+ PermissionConstants.ORGANIZATION_CUSTOM + "'} ] }")
	public List<Role> findByOrgIdAndOrganizationCustomRoleType(Optional<String> orgId);

	@Query("{ $and: [ {'roleType.orgId': ?0}, {'roleType.roleType':'"+ PermissionConstants.PROJECT_CUSTOM + "'}] }")
	public List<Role> findByOrgIdAndProjectCustomRoleType(Optional<String> orgId);

	@Query("{'role': ?0 ,'roleType.roleType': ?1 }")
	public Role findByRoleAndRoleType(String role, String roleType);

	@Query("{ $and: [ {'roleType.projectId': ?0}, {'roleType.roleType':'"+ PermissionConstants.PROJECT_CUSTOM + "'}] }")
	Collection<Role> findByProjectIdAndProjectCustomRoleType(Optional<String> projectId);

	@Query("{'roleType.roleType':'"+ PermissionConstants.PROJECT_CUSTOM +"'}")
	Collection<Role> findByProjectCustomRoleType();

	@Query("{'roleType.roleType':'"+ PermissionConstants.ORGANIZATION_CUSTOM +"'}")
	Collection<Role> findByOrganizationCustomRoleType(Optional<String> orgId);

	@Aggregation(pipeline = {
			"{$unwind: '$permissionIdList'}",
			"{$match: {'permissionIdList': {$nin: ?0}}}",
			"{$group: {'_id': '$_id', 'permissionIdList': {$push: '$permissionIdList'}, " +
					"'role':{$first:'$role'}, 'description':{$first:'$description'}, " +
					"'roleType':{$first:'$roleType'},'created':{$first:'$created'},'updated':{$first:'$updated'}}}",
			"{$set: {'permissionIdList': '$permissionIdList'}}"
	})
	List<Role> removePermissionsIds(List<String> removeIds);
}
