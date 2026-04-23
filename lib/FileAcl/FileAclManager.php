<?php

declare(strict_types=1);

namespace OCA\GroupFolders\FileAcl;

use OCP\Constants;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\IUser;

class FileAclManager {
	private ICache $cache;

	public function __construct(
		private IDBConnection $connection,
		private IGroupManager $groupManager,
		ICacheFactory $cacheFactory,
	) {
		$this->cache = $cacheFactory->createLocal('groupfolders_file_acl');
	}

	private function normalizePath(string $path): string {
		return trim($path, '/');
	}

	public function addPermission(int $folderId, int $fileId, string $filePath, string $mappingType, string $mappingId, int $permissions): void {
		$filePath = $this->normalizePath($filePath);
		$existing = $this->getPermission($folderId, $fileId, $mappingType, $mappingId);
		if ($existing !== null) {
			$query = $this->connection->getQueryBuilder();
			$query->update('group_folders_file_acl')
				->set('permissions', $query->createNamedParameter($permissions, IQueryBuilder::PARAM_INT))
				->set('file_path', $query->createNamedParameter($filePath))
				->where($query->expr()->eq('folder_id', $query->createNamedParameter($folderId, IQueryBuilder::PARAM_INT)))
				->andWhere($query->expr()->eq('file_id', $query->createNamedParameter($fileId, IQueryBuilder::PARAM_INT)))
				->andWhere($query->expr()->eq('mapping_type', $query->createNamedParameter($mappingType)))
				->andWhere($query->expr()->eq('mapping_id', $query->createNamedParameter($mappingId)));
			$query->executeStatement();
		} else {
			$query = $this->connection->getQueryBuilder();
			$query->insert('group_folders_file_acl')
				->values([
					'folder_id' => $query->createNamedParameter($folderId, IQueryBuilder::PARAM_INT),
					'file_id' => $query->createNamedParameter($fileId, IQueryBuilder::PARAM_INT),
					'file_path' => $query->createNamedParameter($filePath),
					'mapping_type' => $query->createNamedParameter($mappingType),
					'mapping_id' => $query->createNamedParameter($mappingId),
					'permissions' => $query->createNamedParameter($permissions, IQueryBuilder::PARAM_INT),
				]);
			$query->executeStatement();
		}

		$this->invalidateCache($folderId, $mappingType, $mappingId);
	}

	public function removePermission(int $folderId, int $fileId, string $mappingType, string $mappingId): void {
		$query = $this->connection->getQueryBuilder();
		$query->delete('group_folders_file_acl')
			->where($query->expr()->eq('folder_id', $query->createNamedParameter($folderId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('file_id', $query->createNamedParameter($fileId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('mapping_type', $query->createNamedParameter($mappingType)))
			->andWhere($query->expr()->eq('mapping_id', $query->createNamedParameter($mappingId)));
		$query->executeStatement();

		$this->invalidateCache($folderId, $mappingType, $mappingId);
	}

	public function getPermission(int $folderId, int $fileId, string $mappingType, string $mappingId): ?int {
		$query = $this->connection->getQueryBuilder();
		$query->select('permissions')
			->from('group_folders_file_acl')
			->where($query->expr()->eq('folder_id', $query->createNamedParameter($folderId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('file_id', $query->createNamedParameter($fileId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('mapping_type', $query->createNamedParameter($mappingType)))
			->andWhere($query->expr()->eq('mapping_id', $query->createNamedParameter($mappingId)));

		$result = $query->executeQuery()->fetchOne();
		return $result !== false ? (int)$result : null;
	}

	public function getPermissionsForFile(int $folderId, int $fileId): array {
		$query = $this->connection->getQueryBuilder();
		$query->select(['id', 'folder_id', 'file_id', 'file_path', 'mapping_type', 'mapping_id', 'permissions'])
			->from('group_folders_file_acl')
			->where($query->expr()->eq('folder_id', $query->createNamedParameter($folderId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('file_id', $query->createNamedParameter($fileId, IQueryBuilder::PARAM_INT)));

		return $query->executeQuery()->fetchAll();
	}

	public function getPermissionsForFolder(int $folderId, string $mappingType, string $mappingId): array {
		$query = $this->connection->getQueryBuilder();
		$query->select(['id', 'folder_id', 'file_id', 'file_path', 'mapping_type', 'mapping_id', 'permissions'])
			->from('group_folders_file_acl')
			->where($query->expr()->eq('folder_id', $query->createNamedParameter($folderId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('mapping_type', $query->createNamedParameter($mappingType)))
			->andWhere($query->expr()->eq('mapping_id', $query->createNamedParameter($mappingId)));

		return $query->executeQuery()->fetchAll();
	}

	public function getEffectivePermissionsForPath(IUser $user, int $folderId, string $path): int {
		$path = $this->normalizePath($path);
		$allPaths = $this->getAllPermittedPathsForUser($user, $folderId);

		$permissions = 0;
		foreach ($allPaths as $permittedPath => $perms) {
			if ($permittedPath === $path) {
				$permissions |= $perms;
			}
		}

		return $permissions;
	}

	public function hasPermissionInSubtree(IUser $user, int $folderId, string $path): bool {
		$path = $this->normalizePath($path);
		$allPaths = $this->getAllPermittedPathsForUser($user, $folderId);

		foreach ($allPaths as $permittedPath => $perms) {
			if (($perms & Constants::PERMISSION_READ) === 0) {
				continue;
			}
			if ($path === '') {
				return true;
			}
			if ($permittedPath === $path || str_starts_with($permittedPath, $path . '/')) {
				return true;
			}
		}

		return false;
	}

	public function getVisibleChildren(IUser $user, int $folderId, string $parentPath): array {
		$parentPath = $this->normalizePath($parentPath);
		$allPaths = $this->getAllPermittedPathsForUser($user, $folderId);

		$children = [];
		$prefix = $parentPath === '' ? '' : $parentPath . '/';
		$prefixLen = strlen($prefix);

		foreach ($allPaths as $permittedPath => $perms) {
			if (($perms & Constants::PERMISSION_READ) === 0) {
				continue;
			}

			if ($prefix === '') {
				$remaining = $permittedPath;
			} elseif (str_starts_with($permittedPath, $prefix)) {
				$remaining = substr($permittedPath, $prefixLen);
			} else {
				continue;
			}

			$parts = explode('/', $remaining);
			if (!empty($parts[0])) {
				$children[$parts[0]] = true;
			}
		}

		return array_keys($children);
	}

	public function getPermissionsForUserInFolder(IUser $user, int $folderId, string $path = ''): array {
		$path = $this->normalizePath($path);
		$allPaths = $this->getAllPermittedPathsForUser($user, $folderId);

		$result = [];
		$prefix = $path === '' ? '' : $path . '/';
		$prefixLen = strlen($prefix);

		foreach ($allPaths as $permittedPath => $perms) {
			if ($path === '' || str_starts_with($permittedPath, $prefix) || $permittedPath === $path) {
				$result[$permittedPath] = $perms;
			}
		}

		return $result;
	}

	private function getAllPermittedPathsForUser(IUser $user, int $folderId): array {
		$cacheKey = $this->getCacheKey($folderId, 'user', $user->getUID());
		$cached = $this->cache->get($cacheKey);
		if ($cached !== null) {
			return $cached;
		}

		$result = [];

		$userRows = $this->queryPermissions($folderId, 'user', $user->getUID());
		foreach ($userRows as $row) {
			$normalizedPath = $this->normalizePath($row['file_path']);
			$result[$normalizedPath] = (int)$row['permissions'];
		}

		$groupIds = $this->groupManager->getUserGroupIds($user);
		foreach ($groupIds as $groupId) {
			$groupCacheKey = $this->getCacheKey($folderId, 'group', $groupId);
			$groupCached = $this->cache->get($groupCacheKey);
			if ($groupCached !== null) {
				foreach ($groupCached as $gpath => $perms) {
					$result[$gpath] = ($result[$gpath] ?? 0) | $perms;
				}
				continue;
			}

			$groupRows = $this->queryPermissions($folderId, 'group', $groupId);
			$groupResult = [];
			foreach ($groupRows as $row) {
				$normalizedPath = $this->normalizePath($row['file_path']);
				$perms = (int)$row['permissions'];
				$groupResult[$normalizedPath] = $perms;
				$result[$normalizedPath] = ($result[$normalizedPath] ?? 0) | $perms;
			}
			$this->cache->set($groupCacheKey, $groupResult, 60);
		}

		$this->cache->set($cacheKey, $result, 60);

		return $result;
	}

	private function queryPermissions(int $folderId, string $mappingType, string $mappingId): array {
		$query = $this->connection->getQueryBuilder();
		$query->select(['file_path', 'permissions'])
			->from('group_folders_file_acl')
			->where($query->expr()->eq('folder_id', $query->createNamedParameter($folderId, IQueryBuilder::PARAM_INT)))
			->andWhere($query->expr()->eq('mapping_type', $query->createNamedParameter($mappingType)))
			->andWhere($query->expr()->eq('mapping_id', $query->createNamedParameter($mappingId)));

		return $query->executeQuery()->fetchAll();
	}

	private function getCacheKey(int $folderId, string $mappingType, string $mappingId): string {
		return "{$folderId}_{$mappingType}_{$mappingId}";
	}

	private function invalidateCache(int $folderId, string $mappingType, string $mappingId): void {
		$this->cache->remove($this->getCacheKey($folderId, $mappingType, $mappingId));
	}

	public function removeAllPermissionsForFolder(int $folderId): void {
		$query = $this->connection->getQueryBuilder();
		$query->delete('group_folders_file_acl')
			->where($query->expr()->eq('folder_id', $query->createNamedParameter($folderId, IQueryBuilder::PARAM_INT)));
		$query->executeStatement();
	}

	public function removeAllPermissionsForFile(int $fileId): void {
		$query = $this->connection->getQueryBuilder();
		$query->delete('group_folders_file_acl')
			->where($query->expr()->eq('file_id', $query->createNamedParameter($fileId, IQueryBuilder::PARAM_INT)));
		$query->executeStatement();
	}

	public function isPathDirectoryVisible(IUser $user, int $folderId, string $dirPath): bool {
		$dirPath = $this->normalizePath($dirPath);
		if ($dirPath === '') {
			return $this->hasPermissionInSubtree($user, $folderId, '');
		}
		return $this->hasPermissionInSubtree($user, $folderId, $dirPath);
	}

	public function getAllFileAclsForFolder(int $folderId): array {
		$query = $this->connection->getQueryBuilder();
		$query->select(['id', 'folder_id', 'file_id', 'file_path', 'mapping_type', 'mapping_id', 'permissions'])
			->from('group_folders_file_acl')
			->where($query->expr()->eq('folder_id', $query->createNamedParameter($folderId, IQueryBuilder::PARAM_INT)));

		return $query->executeQuery()->fetchAll();
	}
}
