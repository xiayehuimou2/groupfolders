<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\ACL;

use OC\Cache\CappedMemoryCache;
use OCA\GroupFolders\ACL\UserMapping\IUserMappingManager;
use OCA\GroupFolders\Trash\TrashManager;
use OCP\Constants;
use OCP\Files\IRootFolder;
use OCP\IUser;
use Psr\Log\LoggerInterface;

class ACLManager {
	private CappedMemoryCache $ruleCache;
	/** @var callable */
	private $rootFolderProvider;

	/** @var CappedMemoryCache 缓存子目录权限检查结果 */
	private CappedMemoryCache $childPermissionCache;

	public function __construct(
		private RuleManager  $ruleManager,
		private TrashManager $trashManager,
		private IUserMappingManager $userMappingManager,
		private LoggerInterface $logger,
		private IUser        $user,
		callable             $rootFolderProvider,
		private ?int         $rootStorageId = null,
		private bool         $inheritMergePerUser = false,
	) {
		$this->ruleCache = new CappedMemoryCache();
		$this->childPermissionCache = new CappedMemoryCache();
		$this->rootFolderProvider = $rootFolderProvider;
	}

	private function getRootStorageId(): int {
		if ($this->rootStorageId === null) {
			$provider = $this->rootFolderProvider;
			/** @var IRootFolder $rootFolder */
			$rootFolder = $provider();
			$this->rootStorageId = $rootFolder->getMountPoint()->getNumericStorageId() ?? -1;
		}

		return $this->rootStorageId;
	}

	/**
	 * Get the list of rules applicable for a set of paths
	 *
	 * @param string[] $paths
	 * @param bool $cache whether to cache the retrieved rules
	 * @return array<string, Rule[]> sorted parent first
	 */
	private function getRules(array $paths, bool $cache = true): array {
		// beware: adding new rules to the cache besides the cap
		// might discard former cached entries, so we can't assume they'll stay
		// cached, so we read everything out initially to be able to return it
		$rules = array_combine($paths, array_map(function (string $path): ?array {
			return $this->ruleCache->get($path);
		}, $paths));

		$nonCachedPaths = array_filter($paths, function (string $path) use ($rules): bool {
			return !isset($rules[$path]);
		});

		if (!empty($nonCachedPaths)) {
			$newRules = $this->ruleManager->getRulesForFilesByPath($this->user, $this->getRootStorageId(), $nonCachedPaths);
			foreach ($newRules as $path => $rulesForPath) {
				if ($cache) {
					$this->ruleCache->set($path, $rulesForPath);
				}
				$rules[$path] = $rulesForPath;
			}
		}

		ksort($rules);

		return $rules;
	}

	/**
	 * Get a list of all path that might contain relevant rules when calculating the permissions for a path
	 *
	 * This contains the $path itself and any parent folder
	 *
	 * @param string $path
	 * @return string[]
	 */
	private function getRelevantPaths(string $path): array {
		$paths = [];
		$fromTrashbin = str_starts_with($path, '__groupfolders/trash/');
		if ($fromTrashbin) {
			/* Exploded path will look like ["__groupfolders", "trash", "1", "folderName.d2345678", "rest/of/the/path.txt"] */
			$parts = explode('/', $path, 5);
			if (count($parts) < 4) {
				// path is the root of the groupfolder trash
				return [];
			}
			[, , $groupFolderId, $rootTrashedItemName] = $parts;
			$groupFolderId = (int)$groupFolderId;
			/* Remove the date part */
			$separatorPos = strrpos($rootTrashedItemName, '.d');
			$rootTrashedItemDate = (int)substr($rootTrashedItemName, $separatorPos + 2);
			$rootTrashedItemName = substr($rootTrashedItemName, 0, $separatorPos);
		}
		while ($path !== '') {
			$paths[] = $path;
			$path = dirname($path);
			if ($fromTrashbin && ($path === '__groupfolders/trash')) {
				/* We are in trash and hit the root folder, continue looking for ACLs on parent folders in original location */
				$trashItemRow = $this->trashManager->getTrashItemByFileName($groupFolderId, $rootTrashedItemName, $rootTrashedItemDate);
				$fromTrashbin = false;
				if ($trashItemRow) {
					$path = dirname('__groupfolders/' . $groupFolderId . '/' . $trashItemRow['original_location']);
					continue;
				} else {
					$this->logger->warning("failed to find trash item for $rootTrashedItemName deleted at $rootTrashedItemDate in folder $groupFolderId", ['app' => 'groupfolders']);
				}
			}

			if ($path === '.' || $path === '/') {
				$path = '';
			}
		}

		return $paths;
	}

	/**
	 * Get the list of rules applicable for a set of paths, including rules for any parent
	 *
	 * @param string[] $paths
	 * @param bool $cache whether to cache the retrieved rules
	 * @return array<string, Rule[]> sorted parent first
	 */
	public function getRelevantRulesForPath(array $paths, bool $cache = true): array {
		$allPaths = [];
		foreach ($paths as $path) {
			$allPaths = array_unique(array_merge($allPaths, $this->getRelevantPaths($path)));
		}
		return $this->getRules($allPaths, $cache);
	}

	public function getACLPermissionsForPath(string $path): int {
		$path = ltrim($path, '/');
		$rules = $this->getRules($this->getRelevantPaths($path));

		$hasAnyRules = false;
		foreach ($rules as $rulesForPath) {
			if (!empty($rulesForPath)) {
				$hasAnyRules = true;
				break;
			}
		}

		if (!$hasAnyRules) {
			return 0;
		}

		return $this->calculatePermissionsForPath($rules);
	}

	public function hasAclRulesForPath(string $path): bool {
		$path = ltrim($path, '/');
		$rules = $this->getRules($this->getRelevantPaths($path));
		foreach ($rules as $rulesForPath) {
			if (!empty($rulesForPath)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check what the effective permissions would be for the current user for a path would be with a new set of rules
	 *
	 * @param list<Rule> $newRules
	 */
	public function testACLPermissionsForPath(string $path, array $newRules): int {
		$path = ltrim($path, '/');
		$rules = $this->getRules($this->getRelevantPaths($path));

		$rules[$path] = $this->filterApplicableRulesToUser($newRules);

		$hasAnyRules = false;
		foreach ($rules as $rulesForPath) {
			if (!empty($rulesForPath)) {
				$hasAnyRules = true;
				break;
			}
		}

		if (!$hasAnyRules) {
			return Constants::PERMISSION_ALL;
		}

		return $this->calculatePermissionsForPath($rules);
	}

	/**
	 * @param string $path
	 * @param array<string, Rule[]> $rules list of rules per path
	 * @return int
	 */
	public function getPermissionsForPathFromRules(string $path, array $rules): int {
		$path = ltrim($path, '/');
		$relevantPaths = $this->getRelevantPaths($path);
		$rules = array_intersect_key($rules, array_flip($relevantPaths));
		return $this->calculatePermissionsForPath($rules);
	}

	/**
	 * @param array<string, Rule[]> $rules list of rules per path, sorted parent first
	 * @return int
	 */
	private function calculatePermissionsForPath(array $rules): int {
		$rulesPerMapping = [];
		foreach ($rules as $rulesForPath) {
			foreach ($rulesForPath as $rule) {
				$mapping = $rule->getUserMapping();
				$key = $mapping->getType() . '/' . $mapping->getId();
				if (!isset($rulesPerMapping[$key])) {
					$rulesPerMapping[$key] = Rule::defaultRule();
				}

				$rulesPerMapping[$key]->applyRule($rule);
			}
		}

		$mergedRule = Rule::mergeRules($rulesPerMapping);
		return $mergedRule->applyPermissions(Constants::PERMISSION_ALL);
	}

	/**
	 * Get the combined "lowest" permissions for an entire directory tree
	 *
	 * @param string $path
	 * @return int
	 */
	public function getPermissionsForTree(string $path): int {
		$path = ltrim($path, '/');
		$rules = $this->ruleManager->getRulesForPrefix($this->user, $this->getRootStorageId(), $path);

		$pathsWithRules = array_keys($rules);
		$permissions = Constants::PERMISSION_ALL;
		foreach ($pathsWithRules as $path) {
			$permissions &= $this->getACLPermissionsForPath($path);
		}
		return $permissions;
	}

	/**
	 * 检查目录是否有子项具有读或编辑权限
	 * 用于实现"隐藏的可见"功能：父目录无权限但子项有权限时，父目录可见
	 * 
	 * @param string $path 目录路径
	 * @return bool 是否有子项具有读/编辑权限
	 */
	public function hasChildWithReadOrEditPermission(string $path): bool {
		$path = ltrim($path, '/');
		
		// 检查缓存
		if ($this->childPermissionCache->hasKey($path)) {
			return $this->childPermissionCache->get($path);
		}
		
		// 获取所有子路径的规则
		$rules = $this->ruleManager->getRulesForPrefix($this->user, $this->getRootStorageId(), $path);
		
		$hasChildPermission = false;
		
		foreach ($rules as $childPath => $childRules) {
			// 排除当前目录本身
			if ($childPath === $path) {
				continue;
			}
			
			// 检查子项是否有读或编辑权限
			$childPermissions = $this->getACLPermissionsForPath($childPath);
			$hasRead = ($childPermissions & Constants::PERMISSION_READ) !== 0;
			$hasEdit = ($childPermissions & (Constants::PERMISSION_UPDATE | Constants::PERMISSION_CREATE | Constants::PERMISSION_DELETE)) !== 0;
			
			if ($hasRead || $hasEdit) {
				$hasChildPermission = true;
				break;
			}
		}
		
		// 缓存结果
		$this->childPermissionCache->set($path, $hasChildPermission);
		
		return $hasChildPermission;
	}

	/**
	 * 检查路径是否为"仅回显"目录（本身无权限但因子项有权限而显示）
	 * 
	 * @param string $path 目录路径
	 * @return bool
	 */
	public function isEchoOnlyDirectory(string $path): bool {
		$path = ltrim($path, '/');
		
		// 获取原始权限
		$originalPermissions = $this->getACLPermissionsForPath($path);
		
		// 如果原始权限已经有读权限，则不是仅回显
		if ($originalPermissions & Constants::PERMISSION_READ) {
			return false;
		}
		
		// 检查是否有子项有权限（如果有，则该目录是仅回显）
		return $this->hasChildWithReadOrEditPermission($path);
	}

	public function hasManageACLPermission(string $path): bool {
		$path = ltrim($path, '/');
		$permissions = $this->getACLPermissionsForPath($path);
		return ($permissions & Rule::PERMISSION_MANAGE_ACL) !== 0;
	}

	public function preloadRulesForFolder(string $path): void {
		$this->ruleManager->getRulesForFilesByParent($this->user, $this->getRootStorageId(), $path);
	}

	/**
	 * Filter a list to only the rules applicable to the current user
	 *
	 * @param list<Rule> $rules
	 * @return list<Rule>
	 */
	private function filterApplicableRulesToUser(array $rules): array {
		$userMappings = $this->userMappingManager->getMappingsForUser($this->user);
		return array_values(array_filter($rules, function (Rule $rule) use ($userMappings): bool {
			foreach ($userMappings as $userMapping) {
				if (
					$userMapping->getType() == $rule->getUserMapping()->getType() &&
					$userMapping->getId() == $rule->getUserMapping()->getId()
				) {
					return true;
				}
			}
			return false;
		}));
	}
}
