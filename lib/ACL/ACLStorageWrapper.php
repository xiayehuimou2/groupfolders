<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\ACL;

use Icewind\Streams\IteratorDirectory;
use OC\Files\Storage\Wrapper\Wrapper;
use OCA\GroupFolders\FileAcl\FileAclManager;
use OCA\GroupFolders\Folder\FolderManager;
use OCP\Constants;
use OCP\IUser;

class ACLStorageWrapper extends Wrapper {
	/** @var ACLManager */
	private $aclManager;
	/** @var bool */
	private $inShare;
	private ?FileAclManager $fileAclManager;
	private int $folderId;
	private ?IUser $user;
	private ?FolderManager $folderManager;

	public function __construct($arguments) {
		parent::__construct($arguments);
		$this->aclManager = $arguments['acl_manager'];
		$this->inShare = $arguments['in_share'];
		$this->fileAclManager = $arguments['file_acl_manager'] ?? null;
		$this->folderId = $arguments['folder_id'] ?? 0;
		$this->user = $arguments['user'] ?? null;
		$this->folderManager = $arguments['folder_manager'] ?? null;
	}

	private function getRelativePath(string $path): string {
		$path = ltrim($path, '/');
		$rootPrefix = '__groupfolders/' . $this->folderId;
		if ($path === $rootPrefix) {
			return '';
		}
		$rootPrefixSlash = $rootPrefix . '/';
		if (str_starts_with($path, $rootPrefixSlash)) {
			return substr($path, strlen($rootPrefixSlash));
		}
		return $path;
	}

	private function getACLPermissionsForPath(string $path) {
		// For ACL admins: always return full permissions
		// Check admin status dynamically to ensure it's always up-to-date
		if ($this->folderManager !== null && $this->user !== null) {
			if ($this->folderManager->canManageACL($this->folderId, $this->user)) {
				return Constants::PERMISSION_ALL;
			}
		}
		
		$permissions = $this->aclManager->getACLPermissionsForPath($path);

		if ($this->inShare) {
			$canRead = $permissions & (Constants::PERMISSION_READ + Constants::PERMISSION_SHARE);
		} else {
			$canRead = $permissions & Constants::PERMISSION_READ;
		}

		if ($canRead) {
			return $permissions;
		}

		if ($this->fileAclManager !== null && $this->user !== null) {
			$fileAclPermissions = $this->getFileAclPermissionsForPath($path);
			if ($fileAclPermissions > 0) {
				return $fileAclPermissions;
			}
		}

		if ($this->aclManager->hasReadPermissionInSubtree(ltrim($path, '/'))) {
			return Constants::PERMISSION_READ;
		}

		return 0;
	}

	private function getFileAclPermissionsForPath(string $path): int {
		if ($this->fileAclManager === null || $this->user === null) {
			return 0;
		}

		$relativePath = $this->getRelativePath($path);

		$directPermissions = $this->fileAclManager->getEffectivePermissionsForPath($this->user, $this->folderId, $relativePath);
		if ($directPermissions & Constants::PERMISSION_READ) {
			return $directPermissions;
		}

		if ($this->fileAclManager->isPathDirectoryVisible($this->user, $this->folderId, $relativePath)) {
			return Constants::PERMISSION_READ;
		}

		return 0;
	}

	private function checkPermissions(string $path, int $permissions) {
		return ($this->getACLPermissionsForPath($path) & $permissions) === $permissions;
	}

	public function isReadable($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_READ) && parent::isReadable($path);
	}

	public function isUpdatable($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_UPDATE) && parent::isUpdatable($path);
	}

	public function isCreatable($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_CREATE) && parent::isCreatable($path);
	}

	public function isDeletable($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_DELETE)
			&& $this->canDeleteTree($path)
			&& parent::isDeletable($path);
	}

	public function isSharable($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_SHARE) && parent::isSharable($path);
	}

	public function getPermissions($path) {
		return $this->storage->getPermissions($path) & $this->getACLPermissionsForPath($path);
	}

	public function rename($source, $target) {
		if (strpos($source, $target) === 0) {
			$part = substr($source, strlen($target));
			if (strpos($part, '.ocTransferId') === 0) {
				return $this->checkPermissions($target, Constants::PERMISSION_CREATE) && parent::rename($source, $target);
			}
		}
		$permissions = $this->file_exists($target) ? Constants::PERMISSION_UPDATE : Constants::PERMISSION_CREATE;
		$sourceParent = dirname($source);
		if ($sourceParent === '.') {
			$sourceParent = '';
		}
		$targetParent = dirname($target);
		if ($targetParent === '.') {
			$targetParent = '';
		}
		return  ($sourceParent === $targetParent ||
			$this->checkPermissions($sourceParent, Constants::PERMISSION_DELETE)) &&
			$this->checkPermissions($source, Constants::PERMISSION_UPDATE | Constants::PERMISSION_READ) &&
			$this->checkPermissions($target, $permissions) &&
			parent::rename($source, $target);
	}

	public function opendir($path) {
		$canRead = $this->checkPermissions($path, Constants::PERMISSION_READ);
		if (!$canRead) {
			return false;
		}

		$handle = parent::opendir($path);
		$items = [];
		while (($file = readdir($handle)) !== false) {
			if ($file !== '.' && $file !== '..') {
				if ($this->checkPermissions(trim($path . '/' . $file, '/'), Constants::PERMISSION_READ)) {
					$items[] = $file;
				}
			}
		}

		if ($this->fileAclManager !== null && $this->user !== null) {
			$relativePath = $this->getRelativePath($path);
			$visibleChildren = $this->fileAclManager->getVisibleChildren($this->user, $this->folderId, $relativePath);
			foreach ($visibleChildren as $child) {
				if (!in_array($child, $items) && parent::file_exists($path ? $path . '/' . $child : $child)) {
					$items[] = $child;
				}
			}
		}

		$aclVisibleChildren = $this->aclManager->getVisibleChildren(ltrim($path, '/'));
		foreach ($aclVisibleChildren as $child) {
			if (!in_array($child, $items) && parent::file_exists($path ? $path . '/' . $child : $child)) {
				$items[] = $child;
			}
		}

		return IteratorDirectory::wrap($items);
	}

	public function copy($source, $target) {
		$permissions = $this->file_exists($target) ? Constants::PERMISSION_UPDATE : Constants::PERMISSION_CREATE;
		return $this->checkPermissions($target, $permissions) &&
			$this->checkPermissions($source, Constants::PERMISSION_READ) &&
			parent::copy($source, $target);
	}

	public function touch($path, $mtime = null) {
		$permissions = $this->file_exists($path) ? Constants::PERMISSION_UPDATE : Constants::PERMISSION_CREATE;
		return $this->checkPermissions($path, $permissions) && parent::touch($path, $mtime);
	}

	public function mkdir($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_CREATE) && parent::mkdir($path);
	}

	public function rmdir($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_DELETE)
			&& $this->canDeleteTree($path)
			&& parent::rmdir($path);
	}

	public function unlink($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_DELETE)
			&& $this->canDeleteTree($path)
			&& parent::unlink($path);
	}

	private function canDeleteTree(string $path): int {
		// For ACL admins: always allow deletion
		if ($this->folderManager !== null && $this->user !== null) {
			if ($this->folderManager->canManageACL($this->folderId, $this->user)) {
				return Constants::PERMISSION_DELETE;
			}
		}
		return $this->aclManager->getPermissionsForTree($path) & Constants::PERMISSION_DELETE;
	}

	public function file_put_contents($path, $data) {
		$permissions = $this->file_exists($path) ? Constants::PERMISSION_UPDATE : Constants::PERMISSION_CREATE;
		return $this->checkPermissions($path, $permissions) ? parent::file_put_contents($path, $data) : false;
	}

	public function fopen($path, $mode) {
		if ($mode === 'r' or $mode === 'rb') {
			$permissions = Constants::PERMISSION_READ;
		} else {
			$permissions = $this->file_exists($path) ? Constants::PERMISSION_UPDATE : Constants::PERMISSION_CREATE;
		}
		return $this->checkPermissions($path, $permissions) ? parent::fopen($path, $mode) : false;
	}

	public function writeStream(string $path, $stream, ?int $size = null): int {
		$permissions = $this->file_exists($path) ? Constants::PERMISSION_UPDATE : Constants::PERMISSION_CREATE;
		return $this->checkPermissions($path, $permissions) ? parent::writeStream($path, $stream, $size) : 0;
	}

	public function getCache($path = '', $storage = null) {
		if (!$storage) {
			$storage = $this;
		}
		$sourceCache = parent::getCache($path, $storage);
		return new ACLCacheWrapper($sourceCache, $this->aclManager, $this->inShare, $this->fileAclManager, $this->folderId, $this->user, $this->folderManager);
	}

	public function getMetaData($path) {
		$data = parent::getMetaData($path);

		if ($data && isset($data['permissions'])) {
			$data['scan_permissions'] = isset($data['scan_permissions']) ? $data['scan_permissions'] : $data['permissions'];
			$data['permissions'] &= $this->getACLPermissionsForPath($path);
		}
		return $data;
	}

	public function getScanner($path = '', $storage = null) {
		if (!$storage) {
			$storage = $this->storage;
		}
		return parent::getScanner($path, $storage);
	}

	public function is_dir($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_READ) &&
			parent::is_dir($path);
	}

	public function is_file($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_READ) &&
			parent::is_file($path);
	}

	public function stat($path) {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}
		return parent::stat($path);
	}

	public function filetype($path) {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}
		return parent::filetype($path);
	}

	public function filesize($path): false|int|float {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}
		return parent::filesize($path);
	}

	public function file_exists($path) {
		return $this->checkPermissions($path, Constants::PERMISSION_READ) &&
			parent::file_exists($path);
	}

	public function filemtime($path) {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}
		return parent::filemtime($path);
	}

	public function file_get_contents($path) {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}
		return parent::file_get_contents($path);
	}

	public function getMimeType($path) {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}
		return parent::getMimeType($path);
	}

	public function hash($type, $path, $raw = false) {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}
		return parent::hash($type, $path, $raw);
	}

	public function getETag($path) {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}
		return parent::getETag($path);
	}

	public function getDirectDownload($path) {
		if (!$this->checkPermissions($path, Constants::PERMISSION_READ)) {
			return false;
		}
		return parent::getDirectDownload($path);
	}

	public function getDirectoryContent($directory): \Traversable {
		$yielded = [];
		foreach ($this->getWrapperStorage()->getDirectoryContent($directory) as $data) {
			$data['scan_permissions'] = isset($data['scan_permissions']) ? $data['scan_permissions'] : $data['permissions'];
			$fullPath = rtrim($directory, '/') . '/' . $data['name'];
			$data['permissions'] &= $this->getACLPermissionsForPath($fullPath);

			if ($data['permissions'] > 0) {
				$yielded[$data['name']] = true;
				yield $data;
			}
		}

		if ($this->fileAclManager !== null && $this->user !== null) {
			$relativePath = $this->getRelativePath($directory);
			$visibleChildren = $this->fileAclManager->getVisibleChildren($this->user, $this->folderId, $relativePath);
			foreach ($visibleChildren as $child) {
				if (!isset($yielded[$child])) {
					$childPath = $directory ? $directory . '/' . $child : $child;
					$metaData = parent::getMetaData($childPath);
					if ($metaData) {
						$metaData['scan_permissions'] = $metaData['permissions'];
						$metaData['permissions'] = $this->getACLPermissionsForPath($childPath);
						yield $metaData;
					}
				}
			}
		}

		$aclVisibleChildren = $this->aclManager->getVisibleChildren(ltrim($directory, '/'));
		foreach ($aclVisibleChildren as $child) {
			if (!isset($yielded[$child])) {
				$childPath = $directory ? $directory . '/' . $child : $child;
				$metaData = parent::getMetaData($childPath);
				if ($metaData) {
					$metaData['scan_permissions'] = $metaData['permissions'];
					$metaData['permissions'] = $this->getACLPermissionsForPath($childPath);
					if ($metaData['permissions'] > 0) {
						yield $metaData;
					}
				}
			}
		}
	}
}
