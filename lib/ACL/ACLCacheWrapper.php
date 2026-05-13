<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\ACL;

use OC\Files\Cache\Wrapper\CacheWrapper;
use OCP\Constants;
use OCP\Files\Cache\ICache;
use OCP\Files\Cache\ICacheEntry;
use OCP\Files\Search\ISearchQuery;

class ACLCacheWrapper extends CacheWrapper {
	private ACLManager $aclManager;
	private bool $inShare;
	private bool $isAclManager = false;

	private function getACLPermissionsForPath(string $path, array $rules = []) {
		if ($this->isAclManager) {
			return Constants::PERMISSION_ALL;
		}

		if (!$this->aclManager->hasAclRulesForPath($path)) {
			return 0;
		}

		if ($rules) {
			$permissions = $this->aclManager->getPermissionsForPathFromRules($path, $rules);
		} else {
			$permissions = $this->aclManager->getACLPermissionsForPath($path);
		}

		if ($this->inShare) {
			$minPermissions = Constants::PERMISSION_READ + Constants::PERMISSION_SHARE;
		} else {
			$minPermissions = Constants::PERMISSION_READ;
		}
		$canRead = ($permissions & $minPermissions) === $minPermissions;
		return $canRead ? $permissions : 0;
	}

	public function __construct(ICache $cache, ACLManager $aclManager, bool $inShare, bool $isAclManager = false) {
		parent::__construct($cache);
		$this->aclManager = $aclManager;
		$this->inShare = $inShare;
		$this->isAclManager = $isAclManager;
	}

	protected function formatCacheEntry($entry, array $rules = []) {
		if (isset($entry['permissions'])) {
			$entry['scan_permissions'] = $entry['permissions'];
			$entry['permissions'] &= $this->getACLPermissionsForPath($entry['path'], $rules);
			
			// 如果没有权限，检查是否应该应用隐藏可见功能
			if (!$entry['permissions']) {
				// 判断是否为目录（mimetype='httpd/unix-directory'）
				$isDirectory = isset($entry['mimetype']) && $entry['mimetype'] === 'httpd/unix-directory';
				
				if ($isDirectory) {
					// 检查是否有子项有读/编辑权限
					$hasChildPermission = $this->aclManager->hasChildWithReadOrEditPermission($entry['path']);
					if ($hasChildPermission) {
						// 应用隐藏可见功能：仅赋予读权限
						$entry['permissions'] = Constants::PERMISSION_READ;
						// 添加隐藏可见标记
						$entry['isHiddenVisible'] = true;
					} else {
						return false;
					}
				} else {
					// 文件没有权限则直接过滤掉
					return false;
				}
			}
		}
		return $entry;
	}

	public function getFolderContentsById($fileId) {
		$results = $this->getCache()->getFolderContentsById($fileId);
		$rules = $this->preloadEntries($results);
		$entries = array_map(function ($entry) use ($rules) {
			return $this->formatCacheEntry($entry, $rules);
		}, $results);
		return array_filter(array_filter($entries));
	}

	public function search($pattern) {
		$results = $this->getCache()->search($pattern);
		$this->preloadEntries($results);
		return array_map([$this, 'formatCacheEntry'], $results);
	}

	public function searchByMime($mimetype) {
		$results = $this->getCache()->searchByMime($mimetype);
		$this->preloadEntries($results);
		return array_map([$this, 'formatCacheEntry'], $results);
	}

	public function searchQuery(ISearchQuery $query) {
		$results = $this->getCache()->searchQuery($query);
		$this->preloadEntries($results);
		return array_map([$this, 'formatCacheEntry'], $results);
	}

	/**
	 * @param ICacheEntry[] $entries
	 * @return Rule[][]
	 */
	private function preloadEntries(array $entries): array {
		$paths = array_map(function (ICacheEntry $entry) {
			return $entry->getPath();
		}, $entries);
		return $this->aclManager->getRelevantRulesForPath($paths, false);
	}
}
