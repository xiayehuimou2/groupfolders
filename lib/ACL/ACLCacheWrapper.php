<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\ACL;

use OC\Files\Cache\Wrapper\CacheWrapper;
use OCA\GroupFolders\FileAcl\FileAclManager;
use OCP\Constants;
use OCP\Files\Cache\ICache;
use OCP\Files\Cache\ICacheEntry;
use OCP\Files\Search\ISearchQuery;
use OCP\IUser;

class ACLCacheWrapper extends CacheWrapper {
	private ACLManager $aclManager;
	private bool $inShare;
	private ?FileAclManager $fileAclManager;
	private int $folderId;
	private ?IUser $user;

	private function getACLPermissionsForPath(string $path, array $rules = []) {
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

		if ($canRead) {
			return $permissions;
		}

		if ($this->fileAclManager !== null && $this->user !== null) {
			$cleanPath = ltrim($path, '/');

			$directPermissions = $this->fileAclManager->getEffectivePermissionsForPath($this->user, $this->folderId, $cleanPath);
			if ($directPermissions & Constants::PERMISSION_READ) {
				return $directPermissions;
			}

			if ($this->fileAclManager->isPathDirectoryVisible($this->user, $this->folderId, $cleanPath)) {
				return Constants::PERMISSION_READ;
			}
		}

		return 0;
	}

	public function __construct(ICache $cache, ACLManager $aclManager, bool $inShare, ?FileAclManager $fileAclManager = null, int $folderId = 0, ?IUser $user = null) {
		parent::__construct($cache);
		$this->aclManager = $aclManager;
		$this->inShare = $inShare;
		$this->fileAclManager = $fileAclManager;
		$this->folderId = $folderId;
		$this->user = $user;
	}

	protected function formatCacheEntry($entry, array $rules = []) {
		if (isset($entry['permissions'])) {
			$entry['scan_permissions'] = $entry['permissions'];
			$entry['permissions'] &= $this->getACLPermissionsForPath($entry['path'], $rules);
			if (!$entry['permissions']) {
				return false;
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
		$filtered = array_filter(array_filter($entries));

		if ($this->fileAclManager !== null && $this->user !== null && !empty($results)) {
			$parentPath = $results[0]->getPath();
			$parentDir = dirname($parentPath);
			if ($parentDir === '.' || $parentDir === '/') {
				$parentDir = '';
			}

			$visibleChildren = $this->fileAclManager->getVisibleChildren($this->user, $this->folderId, $parentDir);

			$existingNames = array_map(function ($entry) {
				return $entry['name'] ?? basename($entry['path'] ?? '');
			}, $filtered);

			$allResults = $this->getCache()->getFolderContentsById($fileId);
			$allByName = [];
			foreach ($allResults as $r) {
				$allByName[$r['name']] = $r;
			}

			foreach ($visibleChildren as $child) {
				if (!in_array($child, $existingNames) && isset($allByName[$child])) {
					$entry = $this->formatCacheEntry($allByName[$child], $rules);
					if ($entry) {
						$filtered[] = $entry;
					}
				}
			}
		}

		return $filtered;
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

	private function preloadEntries(array $entries): array {
		$paths = array_map(function (ICacheEntry $entry) {
			return $entry->getPath();
		}, $entries);
		return $this->aclManager->getRelevantRulesForPath($paths, false);
	}
}
