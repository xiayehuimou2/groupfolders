<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\ACL;

use OCA\GroupFolders\ACL\UserMapping\IUserMapping;
use OCA\GroupFolders\ACL\UserMapping\IUserMappingManager;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IDBConnection;
use OCP\IUser;
use OCP\Log\Audit\CriticalActionPerformedEvent;

class RuleManager {
	private IDBConnection $connection;
	private IUserMappingManager $userMappingManager;
	private IEventDispatcher $eventDispatcher;

	public function __construct(IDBConnection $connection, IUserMappingManager $userMappingManager, IEventDispatcher $eventDispatcher) {
		$this->connection = $connection;
		$this->userMappingManager = $userMappingManager;
		$this->eventDispatcher = $eventDispatcher;
	}

	private function createRule(array $data): ?Rule {
		$mapping = $this->userMappingManager->mappingFromId($data['mapping_type'], $data['mapping_id']);
		if ($mapping) {
			return new Rule(
				$mapping,
				(int)$data['fileid'],
				(int)$data['mask'],
				(int)$data['permissions']
			);
		} else {
			return null;
		}
	}

	/**
	 * @param IUser $user
	 * @param int[] $fileIds
	 * @return (Rule[])[] [$fileId => Rule[]]
	 */
	public function getRulesForFilesById(IUser $user, array $fileIds): array {
		$userMappings = $this->userMappingManager->getMappingsForUser($user);

		$query = $this->connection->getQueryBuilder();
		$query->select(['fileid', 'mapping_type', 'mapping_id', 'mask', 'permissions'])
			->from('group_folders_acl')
			->where($query->expr()->in('fileid', $query->createNamedParameter($fileIds, IQueryBuilder::PARAM_INT_ARRAY)))
			->andWhere($query->expr()->orX(...array_map(function (IUserMapping $userMapping) use ($query) {
				return $query->expr()->andX(
					$query->expr()->eq('mapping_type', $query->createNamedParameter($userMapping->getType())),
					$query->expr()->eq('mapping_id', $query->createNamedParameter($userMapping->getId()))
				);
			}, $userMappings)));

		$rows = $query->executeQuery()->fetchAll();

		$result = [];
		foreach ($rows as $row) {
			$rule = $this->createRule($row);
			if ($rule) {
				$result[$row['fileid']] ??= [];
				$result[$row['fileid']][] = $rule;
			}
		}
		return $result;
	}

	/**
	 * @param IUser $user
	 * @param int $storageId
	 * @param string[] $filePaths
	 * @return (Rule[])[] [$path => Rule[]]
	 */
	public function getRulesForFilesByPath(IUser $user, int $storageId, array $filePaths): array {
		$userMappings = $this->userMappingManager->getMappingsForUser($user);

		$hashes = array_map(function (string $path): string {
			return md5(trim($path, '/'));
		}, $filePaths);

		$rows = [];
		foreach (array_chunk($hashes, 1000) as $chunk) {
			$query = $this->connection->getQueryBuilder();
			$query->select(['f.fileid', 'mapping_type', 'mapping_id', 'mask', 'a.permissions', 'f.path'])
				->from('group_folders_acl', 'a')
				->innerJoin('a', 'filecache', 'f', $query->expr()->eq('f.fileid', 'a.fileid'))
				->where($query->expr()->in('f.path_hash', $query->createNamedParameter($chunk, IQueryBuilder::PARAM_STR_ARRAY)))
				->andWhere($query->expr()->eq('f.storage', $query->createNamedParameter($storageId, IQueryBuilder::PARAM_INT)))
				->andWhere($query->expr()->orX(...array_map(function (IUserMapping $userMapping) use ($query) {
					return $query->expr()->andX(
						$query->expr()->eq('mapping_type', $query->createNamedParameter($userMapping->getType())),
						$query->expr()->eq('mapping_id', $query->createNamedParameter($userMapping->getId()))
					);
				}, $userMappings)));

			$rows = array_merge($rows, $query->executeQuery()->fetchAll());
		}


		$result = [];
		foreach ($filePaths as $path) {
			$result[$path] = [];
		}
		return $this->rulesByPath($rows, $result);
	}

	/**
	 * @param IUser $user
	 * @param int $storageId
	 * @param string $parent
	 * @return (Rule[])[] [$path => Rule[]]
	 */
	public function getRulesForFilesByParent(IUser $user, int $storageId, string $parent): array {
		$userMappings = $this->userMappingManager->getMappingsForUser($user);

		$parentId = $this->getId($storageId, $parent);
		if (!$parentId) {
			return [];
		}

		$query = $this->connection->getQueryBuilder();
		$query->select(['f.fileid', 'a.mapping_type', 'a.mapping_id', 'a.mask', 'a.permissions', 'f.path'])
			->from('filecache', 'f')
			->leftJoin('f', 'group_folders_acl', 'a', $query->expr()->eq('f.fileid', 'a.fileid'))
			->andWhere($query->expr()->eq('f.parent', $query->createNamedParameter($parentId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('f.storage', $query->createNamedParameter($storageId, IQueryBuilder::PARAM_INT)))
			->andWhere(
				$query->expr()->orX(
					$query->expr()->andX(
						$query->expr()->isNull('a.mapping_type'),
						$query->expr()->isNull('a.mapping_id')
					),
					...array_map(function (IUserMapping $userMapping) use ($query) {
						return $query->expr()->andX(
							$query->expr()->eq('a.mapping_type', $query->createNamedParameter($userMapping->getType())),
							$query->expr()->eq('a.mapping_id', $query->createNamedParameter($userMapping->getId()))
						);
					}, $userMappings)
				)
			);

		$rows = $query->executeQuery()->fetchAll();

		$result = [];
		foreach ($rows as $row) {
			if ($row['mapping_type'] !== null) {
				$rule = $this->createRule($row);
				if ($rule) {
					$result[$row['path']] ??= [];
					$result[$row['path']][] = $rule;
				}
			}
		}
		return $result;
	}

	private function getId(int $storageId, string $path): int {
		$query = $this->connection->getQueryBuilder();
		$query->select(['fileid'])
			->from('filecache')
			->where($query->expr()->eq('path_hash', $query->createNamedParameter(md5($path), IQueryBuilder::PARAM_STR)))
			->andWhere($query->expr()->eq('storage', $query->createNamedParameter($storageId, IQueryBuilder::PARAM_INT)));

		return (int)$query->executeQuery()->fetch(\PDO::FETCH_COLUMN);
	}

	/**
	 * @param int $storageId
	 * @param string[] $filePaths
	 * @return (Rule[])[] [$path => Rule[]]
	 */
	public function getAllRulesForPaths(int $storageId, array $filePaths): array {
		$hashes = array_map(function (string $path) {
			return md5(trim($path, '/'));
		}, $filePaths);
		$query = $this->connection->getQueryBuilder();
		$query->select(['f.fileid', 'mapping_type', 'mapping_id', 'mask', 'a.permissions', 'f.path'])
			->from('group_folders_acl', 'a')
			->innerJoin('a', 'filecache', 'f', $query->expr()->eq('f.fileid', 'a.fileid'))
			->where($query->expr()->in('f.path_hash', $query->createNamedParameter($hashes, IQueryBuilder::PARAM_STR_ARRAY)))
			->andWhere($query->expr()->eq('f.storage', $query->createNamedParameter($storageId, IQueryBuilder::PARAM_INT)));

		$rows = $query->executeQuery()->fetchAll();

		return $this->rulesByPath($rows);
	}

	private function rulesByPath(array $rows, array $result = []): array {
		foreach ($rows as $row) {
			$rule = $this->createRule($row);
			if ($rule) {
				$result[$row['path']] ??= [];
				$result[$row['path']][] = $rule;
			}
		}

		ksort($result);

		return $result;
	}

	/**
	 * @param int $storageId
	 * @param string $prefix
	 * @return (Rule[])[] [$path => Rule[]]
	 */
	public function getAllRulesForPrefix(int $storageId, string $prefix): array {
		$query = $this->connection->getQueryBuilder();
		$query->select(['f.fileid', 'mapping_type', 'mapping_id', 'mask', 'a.permissions', 'f.path'])
			->from('group_folders_acl', 'a')
			->innerJoin('a', 'filecache', 'f', $query->expr()->eq('f.fileid', 'a.fileid'))
			->where($query->expr()->orX(
				$query->expr()->like('f.path', $query->createNamedParameter($this->connection->escapeLikeParameter($prefix) . '/%')),
				$query->expr()->eq('f.path_hash', $query->createNamedParameter(md5($prefix)))
			))
			->andWhere($query->expr()->eq('f.storage', $query->createNamedParameter($storageId, IQueryBuilder::PARAM_INT)));

		$rows = $query->executeQuery()->fetchAll();

		return $this->rulesByPath($rows);
	}

	/**
	 * @param IUser $user
	 * @param int $storageId
	 * @param string $prefix
	 * @return array (Rule[])[] [$path => Rule[]]
	 */
	public function getRulesForPrefix(IUser $user, int $storageId, string $prefix): array {
		$userMappings = $this->userMappingManager->getMappingsForUser($user);

		$query = $this->connection->getQueryBuilder();
		$query->select(['f.fileid', 'mapping_type', 'mapping_id', 'mask', 'a.permissions', 'f.path'])
			->from('group_folders_acl', 'a')
			->innerJoin('a', 'filecache', 'f', $query->expr()->eq('f.fileid', 'a.fileid'))
			->where($query->expr()->orX(
				$query->expr()->like('f.path', $query->createNamedParameter($this->connection->escapeLikeParameter($prefix) . '/%')),
				$query->expr()->eq('f.path_hash', $query->createNamedParameter(md5($prefix)))
			))
			->andWhere($query->expr()->eq('f.storage', $query->createNamedParameter($storageId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->orX(...array_map(function (IUserMapping $userMapping) use ($query) {
				return $query->expr()->andX(
					$query->expr()->eq('mapping_type', $query->createNamedParameter($userMapping->getType())),
					$query->expr()->eq('mapping_id', $query->createNamedParameter($userMapping->getId()))
				);
			}, $userMappings)));

		$rows = $query->executeQuery()->fetchAll();

		return $this->rulesByPath($rows);
	}

	private function hasRule(IUserMapping $mapping, int $fileId): bool {
		$query = $this->connection->getQueryBuilder();
		$query->select('fileid')
			->from('group_folders_acl')
			->where($query->expr()->eq('fileid', $query->createNamedParameter($fileId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('mapping_type', $query->createNamedParameter($mapping->getType())))
			->andWhere($query->expr()->eq('mapping_id', $query->createNamedParameter($mapping->getId())));
		return (bool)$query->executeQuery()->fetch();
	}

	public function saveRule(Rule $rule): void {
		// Check if the new rule matches inherited permissions from parent
		// If so, delete the rule to maintain strict inheritance
		$shouldDeleteInstead = $this->checkIfMatchesInheritedPermissions($rule);
		if ($shouldDeleteInstead) {
			\OC::$server->getLogger()->debug(
				"ACL rule for {$rule->getUserMapping()->getType()} '{$rule->getUserMapping()->getId()}' on fileid {$rule->getFileId()} matches inherited permissions, deleting instead of saving",
				['app' => 'groupfolders']
			);
			$this->deleteRuleIfExists($rule);
			return;
		}

		if ($this->hasRule($rule->getUserMapping(), $rule->getFileId())) {
			$query = $this->connection->getQueryBuilder();
			$query->update('group_folders_acl')
				->set('mask', $query->createNamedParameter($rule->getMask(), IQueryBuilder::PARAM_INT))
				->set('permissions', $query->createNamedParameter($rule->getPermissions(), IQueryBuilder::PARAM_INT))
				->where($query->expr()->eq('fileid', $query->createNamedParameter($rule->getFileId(), IQueryBuilder::PARAM_INT)))
				->andWhere($query->expr()->eq('mapping_type', $query->createNamedParameter($rule->getUserMapping()->getType())))
				->andWhere($query->expr()->eq('mapping_id', $query->createNamedParameter($rule->getUserMapping()->getId())));
			$query->executeStatement();

			if ($rule->getUserMapping()->getType() === 'user') {
				$logMessage = 'The ACL rule was updated to permission "%s" and mask "%s" for file/folder with id "%s" for user "%s"';
				$params = [
					'permissions' => $rule->getPermissions(),
					'mask' => $rule->getMask(),
					'fileId' => $rule->getFileId(),
					'user' => $rule->getUserMapping()->getDisplayName() . ' (' . $rule->getUserMapping()->getId() . ')',
				];
			} else {
				$logMessage = 'The ACL rule was updated to permission "%s" and mask "%s" for file/folder with id "%s" for group "%s"';
				$params = [
					'permissions' => $rule->getPermissions(),
					'mask' => $rule->getMask(),
					'fileId' => $rule->getFileId(),
					'user' => $rule->getUserMapping()->getDisplayName(),
				];
			}

			$this->eventDispatcher->dispatchTyped(new CriticalActionPerformedEvent($logMessage, $params));
		} else {
			$query = $this->connection->getQueryBuilder();
			$query->insert('group_folders_acl')
				->values([
					'fileid' => $query->createNamedParameter($rule->getFileId(), IQueryBuilder::PARAM_INT),
					'mapping_type' => $query->createNamedParameter($rule->getUserMapping()->getType()),
					'mapping_id' => $query->createNamedParameter($rule->getUserMapping()->getId()),
					'mask' => $query->createNamedParameter($rule->getMask(), IQueryBuilder::PARAM_INT),
					'permissions' => $query->createNamedParameter($rule->getPermissions(), IQueryBuilder::PARAM_INT)
				]);
			$query->executeStatement();

			if ($rule->getUserMapping()->getType() === 'user') {
				$logMessage = 'A new ACL rule was created to permission "%s" and mask "%s" for file/folder with id "%s" for user "%s"';
				$params = [
					'permissions' => $rule->getPermissions(),
					'mask' => $rule->getMask(),
					'fileId' => $rule->getFileId(),
					'user' => $rule->getUserMapping()->getDisplayName() . ' (' . $rule->getUserMapping()->getId() . ')',
				];
			} else {
				$logMessage = 'A new ACL rule was created to permission "%s" and mask "%s" for file/folder with id "%s" for group "%s"';
				$params = [
					'permissions' => $rule->getPermissions(),
					'mask' => $rule->getMask(),
					'fileId' => $rule->getFileId(),
					'group' => $rule->getUserMapping()->getDisplayName(),
				];
			}

			$this->eventDispatcher->dispatchTyped(new CriticalActionPerformedEvent($logMessage, $params));
		}
	}

	public function deleteRule(Rule $rule): void {
		$query = $this->connection->getQueryBuilder();
		$query->delete('group_folders_acl')
			->where($query->expr()->eq('fileid', $query->createNamedParameter($rule->getFileId(), IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('mapping_type', $query->createNamedParameter($rule->getUserMapping()->getType())))
			->andWhere($query->expr()->eq('mapping_id', $query->createNamedParameter($rule->getUserMapping()->getId())));
		$query->executeStatement();

		if ($rule->getUserMapping()->getType() === 'user') {
			$logMessage = 'The ACL rule was deleted for file/folder with id: "%s" for the user "%s"';
			$params = [
				'fileId' => $rule->getFileId(),
				'user' => $rule->getUserMapping()->getDisplayName() . ' (' . $rule->getUserMapping()->getId() . ')',
			];
		} else {
			$logMessage = 'The ACL rule was deleted for file/folder with id: "%s" for the group "%s"';
			$params = [
				'fileId' => $rule->getFileId(),
				'group' => $rule->getUserMapping()->getDisplayName(),
			];
		}

		$this->eventDispatcher->dispatchTyped(new CriticalActionPerformedEvent($logMessage, $params));
	}

	/**
	 * Propagate ACL changes to all children (subdirectories and files) recursively
	 * This ensures that when a parent's ACL is modified, all descendants inherit the change
	 *
	 * @param Rule $rule The rule that was changed on the parent
	 * @param int $storageId The storage ID
	 * @param string $parentPath The parent path (relative to storage root)
	 * @param bool $isDelete Whether this is a deletion operation
	 */
	public function propagateAclChangeToChildren(Rule $rule, int $storageId, string $parentPath, bool $isDelete = false): void {
		// Get all rules for the parent path prefix (includes all children)
		$allRulesByPath = $this->getAllRulesForPrefix($storageId, $parentPath);

		$action = $isDelete ? 'Deleting' : 'Adding/Updating';
		$mappingType = $rule->getUserMapping()->getType();
		$mappingId = $rule->getUserMapping()->getId();
		
		foreach ($allRulesByPath as $childPath => $childRules) {
			// Skip the parent itself
			if ($childPath === $parentPath) {
				continue;
			}

			// Check if this child already has a rule for the same mapping
			$existingRuleForMapping = null;
			foreach ($childRules as $childRule) {
				if ($childRule->getUserMapping()->getType() === $rule->getUserMapping()->getType() &&
					$childRule->getUserMapping()->getId() === $rule->getUserMapping()->getId()) {
					$existingRuleForMapping = $childRule;
					break;
				}
			}

			// Get the fileid for this child path
			$fileId = $this->getId($storageId, $childPath);
			if (!$fileId) {
				continue;
			}

			if ($isDelete) {
				// For deletion: remove the rule from child if it exists
				if ($existingRuleForMapping) {
					$this->deleteRule($existingRuleForMapping);
					\OC::$server->getLogger()->debug(
						"ACL propagation: {$action} rule for {$mappingType} '{$mappingId}' on child path: {$childPath} (fileid: {$fileId})",
						['app' => 'groupfolders']
					);
				}
			} else {
				// For add/update: create or update the rule on child
				$newRule = new Rule(
					$rule->getUserMapping(),
					$fileId,
					$rule->getMask(),
					$rule->getPermissions()
				);
				$this->saveRule($newRule);
				\OC::$server->getLogger()->debug(
					"ACL propagation: {$action} rule for {$mappingType} '{$mappingId}' with mask={$rule->getMask()}, permissions={$rule->getPermissions()} on child path: {$childPath} (fileid: {$fileId})",
					['app' => 'groupfolders']
				);
			}
		}
	}

	/**
	 * Check if a rule matches the inherited permissions from parent directories
	 * This helps determine if we should delete the rule instead of saving it
	 *
	 * @param Rule $rule The rule to check
	 * @return bool True if the rule matches inherited permissions
	 */
	private function checkIfMatchesInheritedPermissions(Rule $rule): bool {
		// Get the file path for this rule
		$query = $this->connection->getQueryBuilder();
		$query->select('path', 'storage')
			->from('filecache')
			->where($query->expr()->eq('fileid', $query->createNamedParameter($rule->getFileId(), IQueryBuilder::PARAM_INT)));
		$row = $query->executeQuery()->fetch();

		if (!$row) {
			return false;
		}

		$path = $row['path'];
		$storageId = (int)$row['storage'];

		\OC::$server->getLogger()->debug(
			"Checking inherited permissions for {$rule->getUserMapping()->getType()} '{$rule->getUserMapping()->getId()}' on fileid {$rule->getFileId()}, path: {$path}",
			['app' => 'groupfolders']
		);

		// Get parent paths
		$parentPaths = $this->getParentPaths($path);
		if (empty($parentPaths)) {
			\OC::$server->getLogger()->debug(
				"No parent paths found for {$path}",
				['app' => 'groupfolders']
			);
			return false;
		}

		// Get inherited permissions for this mapping from parents
		$inheritedPermissions = $this->getInheritedPermissionsForMapping($rule->getUserMapping(), $storageId, $parentPaths);

		if ($inheritedPermissions === null) {
			// No inherited permissions found
			\OC::$server->getLogger()->debug(
				"No inherited permissions found for {$rule->getUserMapping()->getType()} '{$rule->getUserMapping()->getId()}'",
				['app' => 'groupfolders']
			);
			return false;
		}

		\OC::$server->getLogger()->debug(
			"Comparing permissions: rule={$rule->getPermissions()}, inherited={$inheritedPermissions['permissions']}, " .
			"rule mask={$rule->getMask()}, inherited mask={$inheritedPermissions['mask']}",
			['app' => 'groupfolders']
		);

		// CRITICAL: Only compare permissions, not mask!
		// If the effective permissions match inherited permissions, the rule is redundant
		// and should be deleted to enable strict inheritance from parent
		$matches = ($rule->getPermissions() === $inheritedPermissions['permissions']);

		if ($matches) {
			\OC::$server->getLogger()->debug(
				"✓ Rule permissions MATCH inherited permissions ({$rule->getPermissions()}) - will DELETE rule to enable strict inheritance",
				['app' => 'groupfolders']
			);
		} else {
			\OC::$server->getLogger()->debug(
				"✗ Rule permissions DO NOT MATCH inherited (rule: {$rule->getPermissions()}, inherited: {$inheritedPermissions['permissions']}) - will SAVE rule",
				['app' => 'groupfolders']
			);
		}

		return $matches;
	}

	/**
	 * Get parent paths for a given path
	 *
	 * @param string $path The file path
	 * @return array Array of parent paths
	 */
	private function getParentPaths(string $path): array {
		$paths = [];
		while ($path !== '') {
			$path = dirname($path);
			if ($path === '.' || $path === '/') {
				$path = '';
			}
			if ($path !== '') {
				$paths[] = $path;
			}
		}
		return $paths;
	}

	/**
	 * Get inherited permissions for a specific user/group mapping from parent directories
	 *
	 * @param \OCA\GroupFolders\ACL\UserMapping\IUserMapping $mapping The user/group mapping
	 * @param int $storageId The storage ID
	 * @param array $parentPaths Array of parent paths
	 * @return array|null Array with 'mask' and 'permissions' keys, or null if no inheritance found
	 */
	private function getInheritedPermissionsForMapping($mapping, int $storageId, array $parentPaths): ?array {
		if (empty($parentPaths)) {
			return null;
		}

		$hashes = array_map(function (string $path): string {
			return md5(trim($path, '/'));
		}, $parentPaths);

		$query = $this->connection->getQueryBuilder();
		$query->select(['f.fileid', 'a.mask', 'a.permissions', 'f.path'])
			->from('group_folders_acl', 'a')
			->innerJoin('a', 'filecache', 'f', $query->expr()->eq('f.fileid', 'a.fileid'))
			->where($query->expr()->in('f.path_hash', $query->createNamedParameter($hashes, IQueryBuilder::PARAM_STR_ARRAY)))
			->andWhere($query->expr()->eq('f.storage', $query->createNamedParameter($storageId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('a.mapping_type', $query->createNamedParameter($mapping->getType())))
			->andWhere($query->expr()->eq('a.mapping_id', $query->createNamedParameter($mapping->getId())))
			->orderBy('f.path', 'ASC'); // Order by path to process from root to leaf

		$rows = $query->executeQuery()->fetchAll();

		if (empty($rows)) {
			return null;
		}

		// CRITICAL: Correct permission inheritance calculation
		// For each ACL rule from parent to child:
		// 1. Clear the permission bits controlled by this rule (~mask)
		// 2. Apply the new permissions for those controlled bits
		// Example: Parent has mask=31, permissions=1 (read-only)
		// Wrong: (31 & 31) | (1 & 31) = 31 | 1 = 31 ❌
		// Right: (31 & ~31) | (1 & 31) = 0 | 1 = 1 ✓
		$effectivePermissions = \OCP\Constants::PERMISSION_ALL | Rule::PERMISSION_MANAGE_ACL;

		foreach ($rows as $row) {
			$beforePerms = $effectivePermissions;
			// Clear controlled bits with ~mask, then apply new permissions
			$effectivePermissions = ($effectivePermissions & ~$row['mask']) | ($row['permissions'] & $row['mask']);
			
			\OC::$server->getLogger()->debug(
				"Permission inheritance: path={$row['path']}, " .
				"before={$beforePerms}, mask={$row['mask']}, perms={$row['permissions']}, " .
				"after={$effectivePermissions}",
				['app' => 'groupfolders']
			);
		}

		\OC::$server->getLogger()->debug(
			"Final inherited permissions: {$effectivePermissions}",
			['app' => 'groupfolders']
		);

		return [
			'mask' => \OCP\Constants::PERMISSION_ALL | Rule::PERMISSION_MANAGE_ACL,
			'permissions' => $effectivePermissions
		];
	}

	/**
	 * Delete a rule only if it exists
	 *
	 * @param Rule $rule The rule to delete
	 */
	private function deleteRuleIfExists(Rule $rule): void {
		if ($this->hasRule($rule->getUserMapping(), $rule->getFileId())) {
			$this->deleteRule($rule);
		}
	}
}
