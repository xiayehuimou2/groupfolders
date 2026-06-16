<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2019 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\DAV;

use OCA\DAV\Connector\Sabre\Node;
use OCA\GroupFolders\ACL\ACLManagerFactory;
use OCA\GroupFolders\ACL\Rule;
use OCA\GroupFolders\ACL\RuleManager;
use OCA\GroupFolders\ACL\UserMapping\IUserMappingManager;
use OCA\GroupFolders\ACL\UserMapping\UserMapping;
use OCA\GroupFolders\Folder\FolderManager;
use OCA\GroupFolders\Mount\GroupMountPoint;
use OCP\Constants;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IL10N;
use OCP\IUser;
use OCP\IUserSession;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use Sabre\DAV\Exception\BadRequest;
use Sabre\DAV\INode;
use Sabre\DAV\PropFind;
use Sabre\DAV\PropPatch;
use Sabre\DAV\Server;
use Sabre\DAV\ServerPlugin;
use Sabre\Xml\Reader;

class ACLPlugin extends ServerPlugin {
	public const ACL_ENABLED = '{http://nextcloud.org/ns}acl-enabled';
	public const ACL_CAN_MANAGE = '{http://nextcloud.org/ns}acl-can-manage';
	public const ACL_LIST = '{http://nextcloud.org/ns}acl-list';
	public const INHERITED_ACL_LIST = '{http://nextcloud.org/ns}inherited-acl-list';
	public const GROUP_FOLDER_ID = '{http://nextcloud.org/ns}group-folder-id';
	public const IS_HIDDEN_VISIBLE = '{http://nextcloud.org/ns}is-hidden-visible';
	public const ACL_NODE_PATH = '{http://nextcloud.org/ns}acl-node-path';
	public const ACL_MANAGE_LIST = '{http://nextcloud.org/ns}acl-manage-list';
	public const ACL_RULE_OPERATION = '{http://nextcloud.org/ns}acl-rule-operation';
	public const ACL_OPERATION_TYPE = '{http://nextcloud.org/ns}acl-operation-type';

	private ?Server $server = null;
	private ?IUser $user = null;

	public function __construct(
		private RuleManager $ruleManager,
		private IUserSession $userSession,
		private FolderManager $folderManager,
		private IEventDispatcher $eventDispatcher,
		private ACLManagerFactory $aclManagerFactory,
		private IL10N $l10n,
		private IUserMappingManager $userMappingManager,
	) {
	}

	private function isAdmin(string $path): bool {
		$folderId = $this->folderManager->getFolderByPath($path);
		if ($this->user === null) {
			// Happens when sharing with a remote instance
			return false;
		}
		return $this->folderManager->canManageACL($folderId, $this->user);
	}

	private function canManageACLForNode($fileInfo, $mount): bool {
		if ($this->isAdmin($fileInfo->getPath())) {
			return true;
		}
		if ($this->user !== null) {
			$internalPath = trim($mount->getSourcePath() . '/' . $fileInfo->getInternalPath(), '/');
			$aclManager = $this->aclManagerFactory->getACLManager($this->user);
			if ($aclManager->hasManageACLPermission($internalPath)) {
				return true;
			}
		}
		return false;
	}

	public function initialize(Server $server): void {
		$this->server = $server;
		$this->user = $this->userSession->getUser();

		$this->server->on('propFind', [$this, 'propFind']);
		$this->server->on('propPatch', [$this, 'propPatch']);

		$this->server->xml->elementMap[Rule::ACL] = Rule::class;
		$this->server->xml->elementMap[self::ACL_LIST] = function (Reader $reader): array {
			return \Sabre\Xml\Deserializer\repeatingElements($reader, Rule::ACL);
		};
		$this->server->xml->elementMap[self::ACL_MANAGE_LIST] = function (Reader $reader): array {
			return \Sabre\Xml\Deserializer\repeatingElements($reader, Rule::ACL);
		};
		$this->server->xml->elementMap[self::ACL_RULE_OPERATION] = function (Reader $reader): array {
			$elements = \Sabre\Xml\Deserializer\keyValue($reader);
			return [
				'operationType' => $elements[self::ACL_OPERATION_TYPE] ?? '',
				'mappingType' => $elements[Rule::MAPPING_TYPE] ?? '',
				'mappingId' => $elements[Rule::MAPPING_ID] ?? '',
				'mask' => (int)($elements[Rule::MASK] ?? 0),
				'permissions' => (int)($elements[Rule::PERMISSIONS] ?? 0),
			];
		};
	}

	/**
	 * @return string[]
	 */
	private function getParents(string $path): array {
		$paths = [];
		while ($path !== '') {
			$path = dirname($path);
			if ($path === '.' || $path === '/') {
				$path = '';
			}
			$paths[] = $path;
		}

		return $paths;
	}

	public function propFind(PropFind $propFind, INode $node): void {
		if (!$node instanceof Node) {
			return;
		}

		$fileInfo = $node->getFileInfo();
		$mount = $fileInfo->getMountPoint();
		if (!$mount instanceof GroupMountPoint) {
			return;
		}

		$storageId = $mount->getNumericStorageId();
		$path = trim($mount->getSourcePath() . '/' . $fileInfo->getInternalPath(), '/');
		$parentInternalPaths = $this->getParents($fileInfo->getInternalPath());
		$parentPaths = array_map(function (string $internalPath) use ($mount) {
			return trim($mount->getSourcePath() . '/' . $internalPath, '/');
		}, $parentInternalPaths);

		$cachedFolderId = null;
		$cachedCanManage = null;
		$cachedAllCombinedRules = null;
		$cachedUserFilteredDirectRules = null;
		$cachedUserFilteredInheritedByPath = null;
		$cachedInheritedPermissionsResult = null;
		$cachedInheritedPermissionsResultForUser = null;

		$getFolderId = function () use ($fileInfo, &$cachedFolderId): int {
			if ($cachedFolderId === null) {
				$cachedFolderId = $this->folderManager->getFolderByPath($fileInfo->getPath());
			}
			return $cachedFolderId;
		};

		$getCanManage = function () use ($path, &$cachedCanManage, $getFolderId) {
			if ($cachedCanManage === null) {
				if ($this->user === null) {
					$cachedCanManage = false;
				} else {
					$folderId = $getFolderId();
					if ($this->folderManager->canManageACL($folderId, $this->user)) {
						$cachedCanManage = true;
					} else {
						$aclManager = $this->aclManagerFactory->getACLManager($this->user);
						$cachedCanManage = $aclManager->hasManageACLPermission($path);
					}
				}
			}
			return $cachedCanManage;
		};

		$getAllCombinedRules = function () use ($storageId, $path, $parentPaths, &$cachedAllCombinedRules) {
			if ($cachedAllCombinedRules === null) {
				$cachedAllCombinedRules = $this->ruleManager->getAllRulesForPathWithParents($storageId, $path, $parentPaths);
			}
			return $cachedAllCombinedRules;
		};

		$cachedUserMappings = null;
		$getUserMappings = function () use (&$cachedUserMappings) {
			if ($cachedUserMappings === null) {
				$cachedUserMappings = $this->userMappingManager->getMappingsForUser($this->user);
			}
			return $cachedUserMappings;
		};

		$filterRulesForUser = function (array $rules) use ($getUserMappings): array {
			if ($this->user === null) {
				return [];
			}
			$userMappings = $getUserMappings();
			return array_values(array_filter($rules, function (Rule $rule) use ($userMappings): bool {
				foreach ($userMappings as $userMapping) {
					if (
						$userMapping->getType() === $rule->getUserMapping()->getType() &&
						$userMapping->getId() === $rule->getUserMapping()->getId()
					) {
						return true;
					}
				}
				return false;
			}));
		};

		$filterRulesByPathForUser = function (array $rulesByPath) use ($filterRulesForUser): array {
			$result = [];
			foreach ($rulesByPath as $pathKey => $rules) {
				$filtered = $filterRulesForUser($rules);
				if (!empty($filtered)) {
					$result[$pathKey] = $filtered;
				}
			}
			return $result;
		};

		$getDirectRules = function () use ($getCanManage, $getAllCombinedRules, &$cachedUserFilteredDirectRules, $filterRulesForUser) {
			if ($getCanManage()) {
				return $getAllCombinedRules()['direct'];
			}
			if ($cachedUserFilteredDirectRules === null) {
				$cachedUserFilteredDirectRules = $filterRulesForUser($getAllCombinedRules()['direct']);
			}
			return $cachedUserFilteredDirectRules;
		};

		$getInheritedRulesByPath = function () use ($getCanManage, $getAllCombinedRules, &$cachedUserFilteredInheritedByPath, $filterRulesByPathForUser) {
			if ($getCanManage()) {
				return $getAllCombinedRules()['inheritedByPath'];
			}
			if ($cachedUserFilteredInheritedByPath === null) {
				$cachedUserFilteredInheritedByPath = $filterRulesByPathForUser($getAllCombinedRules()['inheritedByPath']);
			}
			return $cachedUserFilteredInheritedByPath;
		};

		$getInheritedPermissionsResult = function () use ($fileInfo, &$cachedInheritedPermissionsResult, $getCanManage, $getAllCombinedRules) {
			if ($cachedInheritedPermissionsResult === null) {
				$rulesByPath = $getAllCombinedRules()['inheritedByPath'];
				ksort($rulesByPath);
				$inheritedPermissionsByMapping = [];
				$inheritedMaskByMapping = [];
				$mappings = [];
				foreach ($rulesByPath as $rules) {
					foreach ($rules as $rule) {
						$mappingKey = $rule->getUserMapping()->getType() . '::' . $rule->getUserMapping()->getId();
						if (!isset($mappings[$mappingKey])) {
							$mappings[$mappingKey] = $rule->getUserMapping();
						}
						if (!isset($inheritedPermissionsByMapping[$mappingKey])) {
							$inheritedPermissionsByMapping[$mappingKey] = Constants::PERMISSION_ALL | Rule::PERMISSION_MANAGE_ACL;
						}
						if (!isset($inheritedMaskByMapping[$mappingKey])) {
							$inheritedMaskByMapping[$mappingKey] = 0;
						}
						$inheritedPermissionsByMapping[$mappingKey] = $rule->applyPermissions($inheritedPermissionsByMapping[$mappingKey]);
						$inheritedMaskByMapping[$mappingKey] |= $rule->getMask();
					}
				}
				$cachedInheritedPermissionsResult = [
					'mappings' => $mappings,
					'permissions' => $inheritedPermissionsByMapping,
					'masks' => $inheritedMaskByMapping,
				];
			}
			return $cachedInheritedPermissionsResult;
		};

		$getInheritedPermissionsResultForUser = function () use ($fileInfo, &$cachedInheritedPermissionsResultForUser, $getInheritedRulesByPath) {
			if ($cachedInheritedPermissionsResultForUser === null) {
				$rulesByPath = $getInheritedRulesByPath();
				ksort($rulesByPath);
				$inheritedPermissionsByMapping = [];
				$inheritedMaskByMapping = [];
				$mappings = [];
				foreach ($rulesByPath as $rules) {
					foreach ($rules as $rule) {
						$mappingKey = $rule->getUserMapping()->getType() . '::' . $rule->getUserMapping()->getId();
						if (!isset($mappings[$mappingKey])) {
							$mappings[$mappingKey] = $rule->getUserMapping();
						}
						if (!isset($inheritedPermissionsByMapping[$mappingKey])) {
							$inheritedPermissionsByMapping[$mappingKey] = Constants::PERMISSION_ALL | Rule::PERMISSION_MANAGE_ACL;
						}
						if (!isset($inheritedMaskByMapping[$mappingKey])) {
							$inheritedMaskByMapping[$mappingKey] = 0;
						}
						$inheritedPermissionsByMapping[$mappingKey] = $rule->applyPermissions($inheritedPermissionsByMapping[$mappingKey]);
						$inheritedMaskByMapping[$mappingKey] |= $rule->getMask();
					}
				}
				$cachedInheritedPermissionsResultForUser = [
					'mappings' => $mappings,
					'permissions' => $inheritedPermissionsByMapping,
					'masks' => $inheritedMaskByMapping,
				];
			}
			return $cachedInheritedPermissionsResultForUser;
		};

		$propFind->handle(self::ACL_LIST, function () use ($getDirectRules) {
			return $getDirectRules();
		});

		$propFind->handle(self::INHERITED_ACL_LIST, function () use ($fileInfo, $getCanManage, $getInheritedPermissionsResultForUser) {
			$result = $getInheritedPermissionsResultForUser();
			return array_map(function ($mapping, $permissions, $mask) use ($fileInfo) {
				return new Rule(
					$mapping,
					$fileInfo->getId(),
					$mask,
					$permissions
				);
			}, $result['mappings'], $result['permissions'], $result['masks']);
		});

		$propFind->handle(self::GROUP_FOLDER_ID, function () use ($getFolderId) {
			return $getFolderId();
		});

		$propFind->handle(self::ACL_ENABLED, function () use ($getFolderId) {
			$folderId = $getFolderId();
			return $this->folderManager->getFolderAclEnabled($folderId);
		});

		$propFind->handle(self::ACL_CAN_MANAGE, function () use ($getCanManage) {
			return $getCanManage();
		});

		$propFind->handle(self::IS_HIDDEN_VISIBLE, function () use ($fileInfo, $path) {
			$permissions = $fileInfo->getPermissions();

			$hasBasicRead = ($permissions & Constants::PERMISSION_READ) !== 0;
			$hasOtherPerms = ($permissions & (Constants::PERMISSION_UPDATE | Constants::PERMISSION_CREATE | Constants::PERMISSION_DELETE | Constants::PERMISSION_SHARE)) !== 0;

			if ($hasBasicRead && !$hasOtherPerms) {
				if ($fileInfo->getType() === \OCP\Files\FileInfo::TYPE_FOLDER) {
					$aclManager = $this->aclManagerFactory->getACLManager($this->user);
					return $aclManager->isEchoOnlyDirectory($path);
				}
			}

			return false;
		});

		$propFind->handle(self::ACL_NODE_PATH, function () use ($path) {
			return $path;
		});

		$propFind->handle(self::ACL_MANAGE_LIST, function () use ($fileInfo, $getCanManage, $getAllCombinedRules, $getInheritedPermissionsResult) {
			if ($getCanManage()) {
				return [];
			}

			$allCombinedRules = $getAllCombinedRules();
			$directRules = $allCombinedRules['direct'];
			$inheritedResult = $getInheritedPermissionsResult();
			$mappings = $inheritedResult['mappings'];
			$inheritedPermissionsByMapping = $inheritedResult['permissions'];

			$manageRules = [];
			$processedMappings = [];

			foreach ($directRules as $rule) {
				$mappingKey = $rule->getUserMapping()->getType() . '::' . $rule->getUserMapping()->getId();
				$mappings[$mappingKey] = $rule->getUserMapping();
				$processedMappings[$mappingKey] = true;

				$effectivePermissions = $rule->getPermissions();
				if (isset($inheritedPermissionsByMapping[$mappingKey])) {
					$effectivePermissions = ($rule->getPermissions() & $rule->getMask()) | ($inheritedPermissionsByMapping[$mappingKey] & ~$rule->getMask());
				}

				if (($effectivePermissions & Rule::PERMISSION_MANAGE_ACL) !== 0) {
					$manageRules[] = new Rule(
						$rule->getUserMapping(),
						$fileInfo->getId(),
						63,
						$effectivePermissions
					);
				}
			}

			foreach ($mappings as $mappingKey => $mapping) {
				if (!isset($processedMappings[$mappingKey]) && isset($inheritedPermissionsByMapping[$mappingKey])) {
					if (($inheritedPermissionsByMapping[$mappingKey] & Rule::PERMISSION_MANAGE_ACL) !== 0) {
						$manageRules[] = new Rule(
							$mapping,
							$fileInfo->getId(),
							63,
							$inheritedPermissionsByMapping[$mappingKey]
						);
					}
				}
			}

			return $manageRules;
		});
	}

	public function propPatch(string $path, PropPatch $propPatch): void {
		$node = $this->server->tree->getNodeForPath($path);
		if (!$node instanceof Node) {
			return;
		}
		$fileInfo = $node->getFileInfo();
		$mount = $fileInfo->getMountPoint();
		if (!$mount instanceof GroupMountPoint || !$this->canManageACLForNode($fileInfo, $mount)) {
			return;
		}

		// Mapping the old property to the new property.
		$propPatch->handle(self::ACL_LIST, function (array $rawRules) use ($path) {
			$node = $this->server->tree->getNodeForPath($path);
			if (!$node instanceof Node) {
				return false;
			}
			$fileInfo = $node->getFileInfo();
			$mount = $fileInfo->getMountPoint();
			if (!$mount instanceof GroupMountPoint) {
				return false;
			}
			if ($this->user === null) {
				return false;
			}

			$path = trim($mount->getSourcePath() . '/' . $fileInfo->getInternalPath(), '/');

			// populate fileid in rules
			$rules = array_map(function (Rule $rule) use ($fileInfo) {
				return new Rule(
					$rule->getUserMapping(),
					$fileInfo->getId(),
					$rule->getMask(),
					$rule->getPermissions()
				);
			}, $rawRules);

			$formattedRules = array_map(function (Rule $rule) {
				return $rule->getUserMapping()->getType() . ' ' . $rule->getUserMapping()->getDisplayName() . ': ' . $rule->formatPermissions();
			}, $rules);
			if (count($formattedRules)) {
				$formattedRules = implode(', ', $formattedRules);
				$this->eventDispatcher->dispatchTyped(new CriticalActionPerformedEvent('The advanced permissions for "%s" in groupfolder with id %d was set to "%s"', [
					$fileInfo->getInternalPath(),
					$mount->getFolderId(),
					$formattedRules,
				]));
			} else {
				$this->eventDispatcher->dispatchTyped(new CriticalActionPerformedEvent('The advanced permissions for "%s" in groupfolder with id %d was cleared', [
					$fileInfo->getInternalPath(),
					$mount->getFolderId(),
				]));
			}

			$aclManager = $this->aclManagerFactory->getACLManager($this->user);
			if (!$this->canManageACLForNode($fileInfo, $mount)) {
				$newPermissions = $aclManager->testACLPermissionsForPath($path, $rules);
				if (!($newPermissions & Constants::PERMISSION_READ)) {
					throw new BadRequest($this->l10n->t('You can not remove your own read permission.'));
				}
			}

			$existingRules = array_reduce(
				$this->ruleManager->getAllRulesForPaths($mount->getNumericStorageId(), [$path]),
				function (array $rules, array $rulesForPath) {
					return array_merge($rules, $rulesForPath);
				},
				[]
			);


			$deletedRules = array_udiff($existingRules, $rules, function ($obj_a, $obj_b) {
				$typeCmp = strcmp($obj_a->getUserMapping()->getType(), $obj_b->getUserMapping()->getType());
				if ($typeCmp !== 0) {
					return $typeCmp;
				}
				return strcmp($obj_a->getUserMapping()->getId(), $obj_b->getUserMapping()->getId());
			});
			foreach ($deletedRules as $deletedRule) {
				$this->ruleManager->deleteRule($deletedRule);
				// Propagate deletion to all children recursively
				$this->ruleManager->propagateAclChangeToChildren($deletedRule, $mount->getNumericStorageId(), $path, true);
			}

			foreach ($rules as $rule) {
				$this->ruleManager->saveRule($rule);
				// Propagate add/update to all children recursively
				$this->ruleManager->propagateAclChangeToChildren($rule, $mount->getNumericStorageId(), $path, false);
			}


			$node->getNode()->getStorage()->getPropagator()->propagateChange($fileInfo->getInternalPath(), $fileInfo->getMtime());

			return true;
		});

		$propPatch->handle(self::ACL_RULE_OPERATION, function (array $operationData) use ($path) {
			$node = $this->server->tree->getNodeForPath($path);
			if (!$node instanceof Node) {
				return false;
			}
			$fileInfo = $node->getFileInfo();
			$mount = $fileInfo->getMountPoint();
			if (!$mount instanceof GroupMountPoint) {
				return false;
			}
			if ($this->user === null) {
				return false;
			}

			$operationType = $operationData['operationType'] ?? '';
			$mappingType = $operationData['mappingType'] ?? '';
			$mappingId = $operationData['mappingId'] ?? '';
			$mask = $operationData['mask'] ?? 0;
			$permissions = $operationData['permissions'] ?? 0;

			if (empty($mappingType) || empty($mappingId)) {
				return false;
			}

			$userMapping = new UserMapping($mappingType, $mappingId);

			$rule = new Rule(
				$userMapping,
				$fileInfo->getId(),
				$mask,
				$permissions
			);

			$fullPath = trim($mount->getSourcePath() . '/' . $fileInfo->getInternalPath(), '/');

			$this->eventDispatcher->dispatchTyped(new CriticalActionPerformedEvent(
				'ACL rule %s: %s "%s" on "%s" in groupfolder with id %d (mask=%d, permissions=%d)',
				[
					$operationType,
					$mappingType,
					$mappingId,
					$fileInfo->getInternalPath(),
					$mount->getFolderId(),
					$mask,
					$permissions,
				]
			));

			$aclManager = $this->aclManagerFactory->getACLManager($this->user);
			if (!$this->canManageACLForNode($fileInfo, $mount)) {
				$newPermissions = $aclManager->testACLPermissionsForPath($fullPath, [$rule]);
				if (!($newPermissions & Constants::PERMISSION_READ)) {
					throw new BadRequest($this->l10n->t('You can not remove your own read permission.'));
				}
			}

			switch ($operationType) {
				case 'add':
					$this->ruleManager->saveRule($rule);
					$this->ruleManager->propagateRuleToAllChildren($rule, $mount->getNumericStorageId(), $fullPath);
					break;
				case 'update':
					$this->ruleManager->saveRule($rule);
					$this->ruleManager->propagateRuleUpdateToChildren($rule, $mount->getNumericStorageId(), $fullPath);
					break;
				case 'delete':
					$this->ruleManager->deleteRuleOrDeny($rule);
					$this->ruleManager->propagateRuleDeleteToChildren($rule, $mount->getNumericStorageId(), $fullPath);
					break;
				default:
					return false;
			}

			$node->getNode()->getStorage()->getPropagator()->propagateChange($fileInfo->getInternalPath(), $fileInfo->getMtime());

			return true;
		});
	}
}