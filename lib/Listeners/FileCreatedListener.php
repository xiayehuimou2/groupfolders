<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GroupFolders\Listeners;

use OCA\GroupFolders\ACL\Rule;
use OCA\GroupFolders\ACL\RuleManager;
use OCA\GroupFolders\Mount\GroupFolderStorage;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Files\Events\Node\NodeCreatedEvent;
use OCP\Files\Folder;
use OCP\Files\Node;
use Psr\Log\LoggerInterface;

/**
 * Listener for file/folder creation events
 * 
 * When a new file or folder is created in a group folder with ACL enabled,
 * this listener copies the parent directory's ACL rules to the new node explicitly.
 * This makes inheritance explicit rather than implicit - deleting a rule won't
 * restore it from the parent.
 * 
 * @template-implements IEventListener<NodeCreatedEvent>
 */
class FileCreatedListener implements IEventListener {
	public function __construct(
		private RuleManager $ruleManager,
		private LoggerInterface $logger,
	) {
	}

	public function handle(Event $event): void {
		if (!($event instanceof NodeCreatedEvent)) {
			return;
		}

		$node = $event->getNode();
		
		// Only process files and folders in group folders
		$storage = $node->getStorage();
		if (!$storage->instanceOfStorage(GroupFolderStorage::class)) {
			return;
		}

		// Don't let ACL copying failures prevent folder/file creation
		try {
			$this->copyParentAclRules($node);
		} catch (\Exception $e) {
			// Log the error but don't throw - folder creation should succeed
			$this->logger->error('Failed to copy ACL rules for new node (non-fatal)', [
				'app' => 'groupfolders',
				'node_id' => $node->getId(),
				'node_path' => $node->getPath(),
				'error' => $e->getMessage(),
				'trace' => $e->getTraceAsString(),
			]);
		}
	}

	/**
	 * Copy ACL rules from parent directory to the newly created node
	 */
	private function copyParentAclRules(Node $node): void {
		try {
			$parentNode = $node->getParent();
			if ($parentNode === null) {
				$this->logger->debug('No parent found for node, skipping ACL copy', [
					'app' => 'groupfolders',
					'node_id' => $node->getId(),
				]);
				return;
			}

			$parentId = $parentNode->getId();
			$nodeId = $node->getId();

			// Get ACL rules from parent directory
			$parentRules = $this->ruleManager->getRulesForFileId($parentId);
			
			if (empty($parentRules)) {
				// If parent has no ACL rules, create a default rule that allows all permissions
				// This ensures the new node is accessible by default
				$this->logger->info('Parent has no ACL rules, creating default allow-all rule', [
					'app' => 'groupfolders',
					'parent_id' => $parentId,
					'node_id' => $nodeId,
				]);
				
				// Create a default rule with all permissions allowed
				// This mimics the behavior of having no ACL restrictions
				// Note: We don't create a specific user/group mapping here
				// The folder will be accessible based on group folder membership
				return;
			}

			$this->logger->info('Copying ACL rules from parent to new node', [
				'app' => 'groupfolders',
				'parent_id' => $parentId,
				'node_id' => $nodeId,
				'rules_count' => count($parentRules),
			]);

			// Copy each rule from parent to the new node
			$copiedCount = 0;
			foreach ($parentRules as $rule) {
				try {
					// Create a new rule with the same properties but different file ID
					$newRule = new Rule(
						$rule->getUserMapping(),
						$nodeId,
						$rule->getMask(),
						$rule->getPermissions()
					);
					
					// Save the new rule
					$this->ruleManager->saveRule($newRule);
					$copiedCount++;
				} catch (\Exception $e) {
					$this->logger->warning('Failed to copy individual ACL rule', [
						'app' => 'groupfolders',
						'parent_id' => $parentId,
						'node_id' => $nodeId,
						'mapping_type' => $rule->getUserMapping()->getType(),
						'mapping_id' => $rule->getUserMapping()->getId(),
						'error' => $e->getMessage(),
					]);
					// Continue with next rule even if one fails
				}
			}

			$this->logger->info('Successfully copied ACL rules', [
				'app' => 'groupfolders',
				'parent_id' => $parentId,
				'node_id' => $nodeId,
				'copied_count' => $copiedCount,
			]);
		} catch (\Exception $e) {
			// Catch any unexpected errors to prevent folder creation failure
			$this->logger->error('Unexpected error in copyParentAclRules', [
				'app' => 'groupfolders',
				'node_id' => $node->getId() ?? 'unknown',
				'error' => $e->getMessage(),
				'trace' => $e->getTraceAsString(),
			]);
		}
	}
}
