package com.albanero.authservice.repository;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.RolePermissions;

@Repository
public interface RolePermissionsRepository extends MongoRepository<RolePermissions, String> {
	public RolePermissions findByRoleId(String roleId);
}
