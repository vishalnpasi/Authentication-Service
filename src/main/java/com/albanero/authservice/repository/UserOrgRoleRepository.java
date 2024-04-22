package com.albanero.authservice.repository;

import java.util.List;

import org.springframework.data.mongodb.repository.Aggregation;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import com.albanero.authservice.model.UserOrgRole;

@Repository
public interface UserOrgRoleRepository extends MongoRepository<UserOrgRole, String> {

	public UserOrgRole findByUserId(String userId);

	@Aggregation(pipeline = {
			"{$match: {'projectOrgRoleIdList.projectOrganizationRoleId':{$in: ?0}}}"
	})
	public List<UserOrgRole> findByProjectOrgRoleIdListIn(List<String> projectOrgRoleIdList);

	public List<UserOrgRole> findByOrgRoleIdListIn(List<String> orgRoleIdList);

	public void deleteByUserId(String userId);

	@Aggregation(pipeline = {
			"{$unwind: '$orgRoleIdList'}",
			"{$match: {'orgRoleIdList': {$nin: ?0}}}",
			"{$group: {'_id': '$_id', 'orgRoleIdList': {$push: '$orgRoleIdList'}, " +
					"'userId':{$first:'$userId'}, 'platformRoleIdList':{$first:'$platformRoleIdList'}, " +
					"'projectOrgRoleIdList':{$first:'$projectOrgRoleIdList'}}}",
			"{$set: {'orgRoleIdList': '$orgRoleIdList'}}",

			"{$unwind: '$platformRoleIdList'}",
			"{$match: {'platformRoleIdList': {$nin: ?1}}}",
			"{$group: {'_id': '$_id', 'platformRoleIdList': {$push: '$platformRoleIdList'}, " +
					"'userId':{$first:'$userId'}, 'projectOrgRoleIdList':{$first:'$projectOrgRoleIdList'}, " +
					"'orgRoleIdList':{$first:'$orgRoleIdList'}}}",
			"{$set: {'platformRoleIdList': '$platformRoleIdList'}}",

			"{$unwind: '$projectOrgRoleIdList'}",
			"{$match: {'projectOrgRoleIdList.projectOrganizationRoleId': {$nin: ?2}}}",
			"{$group: {'_id': '$_id', 'projectOrgRoleIdList': {$push: '$projectOrgRoleIdList'}, " +
					"'userId':{$first:'$userId'}, 'platformRoleIdList':{$first:'$platformRoleIdList'}, " +
					"'orgRoleIdList':{$first:'$orgRoleIdList'}}}",
			"{$set: {'projectOrgRoleIdList': '$projectOrgRoleIdList'}}"
	})
	List<UserOrgRole> removeOrganizationRoleIdsAndPlatformRoleIdListAndProjectOrgRoleIdList(
			List<String> removedOrgRoleIdList,
			List<String> removedRoles,
			List<String> removedProjectOrgRoleIdList
	);
}
