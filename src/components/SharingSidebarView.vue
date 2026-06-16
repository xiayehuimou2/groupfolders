<!--
  - SPDX-FileCopyrightText: 2018 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->
<template>
	<div v-if="aclEnabled && !loading && (isAdmin || currentUserEffectivePermission > 0 || manageDisplayList.length > 0)" id="groupfolder-acl-container" :class="{ 'admin-mode': isAdmin }">
		<div class="acl-add-row">
			<NcButton v-if="isAdmin && !loading && !showAclCreate"
				@click="toggleAclCreate">
				<template #icon>
					<Plus :size="16" />
				</template>
				{{ t('groupfolders', 'Add advanced permission rule') }}
			</NcButton>
			<div v-if="isAdmin && !loading && showAclCreate" class="acl-select-wrapper">
				<NcSelect
					ref="select"
					v-model="value"
					:options="options"
					:loading="isSearching"
					:filterable="false"
					:placeholder="t('groupfolders', 'Select a user or group')"
					:get-option-key="() => 'unique'"
					@input="createAcl"
					@search="searchMappings">
					<template #option="option">
						<NcAvatar :user="option.id" :is-no-user="option.type !== 'user'" />
						{{ option.label }}
					</template>
				</NcSelect>
				<NcButton
					type="tertiary"
					:aria-label="t('groupfolders', 'Cancel')"
					@click="toggleAclCreate">
					<template #icon>
						<Close :size="16" />
					</template>
				</NcButton>
			</div>
		</div>
		<div class="groupfolder-entry">
			<div class="avatar icon-group-white" />
			<span class="username" />
		</div>
		<table>
			<thead>
			<tr>
				<th />
				<th>{{ t('groupfolders', 'Group folder') }}</th>
				<th class="permissions-column">
					{{ t('groupfolders', 'Permissions') }}
				</th>
				<th v-if="isAdmin" class="state-column" />
			</tr>
			</thead>
			<tbody v-if="isAdmin">
			<tr v-for="item in displayList" :key="item.mappingType + '-' + item.mappingId">
				<td>
					<NcAvatar :user="item.mappingId" :is-no-user="item.mappingType !== 'user'" :size="24" />
				</td>
				<td v-tooltip="getFullDisplayName(item.mappingDisplayName, item.mappingType)" class="username">
					{{ getFullDisplayName(item.mappingDisplayName, item.mappingType) }}
				</td>
				<td class="permissions-column">
					<span v-if="editingItemId !== item.mappingId"
						class="permission-text"
						@click="startEditing(item)">
						{{ getPermissionLabel(item) }}
					</span>
					<NcSelect v-else
						ref="permissionSelect"
						class="permission-select"
						:options="permissionOptions"
						:value="getPermissionOption(item)"
						:disabled="loading"
						:placeholder="t('groupfolders', 'No permission')"
						:append-to-body="false"
						@input="changePermission(item, $event)"
						@close="stopEditing" />
				</td>
				<td class="state-column">
					<NcButton
						type="tertiary"
						:v-tooltip="t('groupfolders', 'Remove access rule')"
						:aria-label="t('groupfolders', 'Remove access rule')"
						@click="removeAcl(item)">
						<template #icon>
							<Delete :size="16" />
						</template>
					</NcButton>
				</td>
			</tr>
			</tbody>
			<tbody v-else>
			<tr v-for="item in manageDisplayList" :key="'manage-' + item.mappingType + '-' + item.mappingId">
				<td>
					<NcAvatar :user="item.mappingId" :is-no-user="item.mappingType !== 'user'" :size="24" />
				</td>
				<td v-tooltip="getFullDisplayName(item.mappingDisplayName, item.mappingType)" class="username">
					{{ getFullDisplayName(item.mappingDisplayName, item.mappingType) }}
				</td>
				<td class="permissions-column">
					<span class="permission-text readonly">
						{{ getPermissionLabel(item) }}
					</span>
				</td>
			</tr>
			<tr v-if="currentUserEffectivePermission > 0">
				<td>
					<NcAvatar user="admin" :size="24" />
				</td>
				<td class="username">
					{{ t('groupfolders', 'You') }}
				</td>
				<td class="permissions-column">
					<span class="permission-text readonly">
						{{ getPermissionLabel({ permissions: currentUserEffectivePermission }) }}
					</span>
				</td>
			</tr>
			</tbody>
		</table>
	</div>
</template>

<script>
import axios from '@nextcloud/axios'
import { showError } from '@nextcloud/dialogs'
import { generateUrl } from '@nextcloud/router'
import NcAvatar from '@nextcloud/vue/dist/Components/NcAvatar.js'
import NcButton from '@nextcloud/vue/dist/Components/NcButton.js'
import NcSelect from '@nextcloud/vue/dist/Components/NcSelect.js'
import Tooltip from '@nextcloud/vue/dist/Directives/Tooltip.js'
import Vue from 'vue'
import Close from 'vue-material-design-icons/Close.vue'
import Delete from 'vue-material-design-icons/Delete.vue'
import Plus from 'vue-material-design-icons/Plus.vue'
import logger from '../services/logger.ts'
import BinaryTools from './../BinaryTools.js'
import client from './../client.js'
import Rule from './../model/Rule.js'
import AclStateButton, { STATES } from './AclStateButton.vue'

let searchRequestCancelSource = null
const PERMISSION_MANAGE_ACL = 32

export default {
	name: 'SharingSidebarView',
	directives: {
		tooltip: Tooltip,
	},
	components: {
		NcAvatar,
		NcSelect,
		NcButton,
		AclStateButton,
		Close,
		Plus,
		Delete,
	},
	props: {
		fileInfo: {
			type: Object,
			required: true,
		},
	},
	data() {
		return {
			aclEnabled: false,
			aclCanManage: false,
			showAclCreate: false,
			groupFolderId: null,
			aclNodePath: null,
			loading: false,
			isSearching: false,
			options: [],
			value: null,
			model: null,
			list: [],
			manageAclList: [],
			editingItemId: null,
			permissionOptions: [
				{ label: t('groupfolders', 'Read'), value: 'read' },
				{ label: t('groupfolders', 'Edit'), value: 'edit' },
				{ label: t('groupfolders', 'Manage'), value: 'manage' }
			]
		}
	},
	computed: {
		isAdmin() {
			return this.aclCanManage
		},
		currentUserEffectivePermission() {
			let permissions = 0
			for (const item of this.list) {
				permissions |= item.permissions
			}
			return permissions
		},
		displayList() {
			return this.list.filter(item => item.permissions !== 0)
		},
		manageDisplayList() {
			return this.manageAclList.filter(item => item.permissions !== 0)
		},
		isNotInherited() {
			return (permission, mask) => {
				return (permission & ~mask) === 0
			}
		},
		isAllowed() {
			return (permission, permissions) => {
				return (permission & permissions) > 0
			}
		},
		getState() {
			return (permission, item) => {
				const permitted = this.isAllowed(permission, item.permissions)
				if (this.isNotInherited(permission, item.mask)) {
					return permitted ? STATES.SELF_ALLOW : STATES.SELF_DENY
				} else {
					const inheritPermitted = this.isAllowed(permission, item.inheritedPermissions)
					if (this.isNotInherited(permission, item.inheritedMask)) {
						return inheritPermitted ? STATES.INHERIT_ALLOW : STATES.INHERIT_DENY
					} else {
						return STATES.INHERIT_DEFAULT
					}
				}
			}
		},
		getEditState() {
			return (item) => {
				const EDIT_PERMS = OC.PERMISSION_UPDATE | OC.PERMISSION_CREATE | OC.PERMISSION_DELETE;
				const allEditMasked = (item.mask & EDIT_PERMS) === EDIT_PERMS;
				
				if (allEditMasked) {
					const allEditPermitted = (item.permissions & EDIT_PERMS) === EDIT_PERMS;
					return allEditPermitted ? STATES.SELF_ALLOW : STATES.SELF_DENY;
				}
				
				// Check each edit permission bit individually
				const permsToCheck = [OC.PERMISSION_UPDATE, OC.PERMISSION_CREATE, OC.PERMISSION_DELETE];
				for (const perm of permsToCheck) {
					const masked = (item.mask & perm) !== 0;
					if (masked) {
						continue;
					}
					const inheritMasked = (item.inheritedMask & perm) !== 0;
					const inheritPermitted = (item.inheritedPermissions & perm) !== 0;
					if (inheritMasked) {
						return inheritPermitted ? STATES.INHERIT_ALLOW : STATES.INHERIT_DENY;
					}
				}
				
				// If no inherited permission is explicitly set, check if all inherited permissions are allowed
				const allInheritEditPermitted = (item.inheritedPermissions & EDIT_PERMS) === EDIT_PERMS;
				if (allInheritEditPermitted) {
					return STATES.INHERIT_ALLOW;
				}
				
				return STATES.INHERIT_DENY;
			}
		},
		getUserPermissionOption() {
			return (item) => {
				const EDIT_PERMS = OC.PERMISSION_UPDATE | OC.PERMISSION_CREATE | OC.PERMISSION_DELETE;
				const hasRead = (item.permissions & OC.PERMISSION_READ) !== 0;
				const hasEdit = (item.permissions & EDIT_PERMS) !== 0;
				const hasManage = (item.permissions & PERMISSION_MANAGE_ACL) !== 0;
				
				if (hasManage && hasEdit && hasRead) {
					return { label: t('groupfolders', 'Manage'), value: 'manage' };
				} else if (hasEdit && hasRead) {
					return { label: t('groupfolders', 'Edit'), value: 'edit' };
				} else if (hasRead) {
					return { label: t('groupfolders', 'Read'), value: 'read' };
				}
				return null;
			}
		},
		getPermissionLabel() {
			return (item) => {
				if (!item) return t('groupfolders', 'No permission');
				const EDIT_PERMS = OC.PERMISSION_UPDATE | OC.PERMISSION_CREATE | OC.PERMISSION_DELETE;
				const hasRead = (item.permissions & OC.PERMISSION_READ) !== 0;
				const hasEdit = (item.permissions & EDIT_PERMS) !== 0;
				const hasManage = (item.permissions & PERMISSION_MANAGE_ACL) !== 0;
				
				if (hasManage && hasEdit && hasRead) {
					return t('groupfolders', 'Manage');
				} else if (hasEdit && hasRead) {
					return t('groupfolders', 'Edit');
				} else if (hasRead) {
					return t('groupfolders', 'Read');
				}
				return t('groupfolders', 'No permission');
			}
		},
		getPermissionOption() {
			return (item) => {
				const EDIT_PERMS = OC.PERMISSION_UPDATE | OC.PERMISSION_CREATE | OC.PERMISSION_DELETE;
				const hasRead = (item.permissions & OC.PERMISSION_READ) !== 0;
				const hasEdit = (item.permissions & EDIT_PERMS) !== 0;
				const hasManage = (item.permissions & PERMISSION_MANAGE_ACL) !== 0;
				
				if (hasManage && hasEdit && hasRead) {
					return { label: t('groupfolders', 'Manage'), value: 'manage' };
				} else if (hasEdit && hasRead) {
					return { label: t('groupfolders', 'Edit'), value: 'edit' };
				} else if (hasRead) {
					return { label: t('groupfolders', 'Read'), value: 'read' };
				}
				return null;
			}
		},
	},
	watch: {
		fileInfo(/* newVal, oldVal */) {
			// reload ACL entries if file changes
			this.loadAcls()
		},
	},
	beforeMount() {
		// load ACL entries for initial file
		this.loadAcls()
	},
	methods: {
		loadAcls() {
			this.options = []
			this.loading = true
			this.model = JSON.parse(JSON.stringify(this.fileInfo))
			client.propFind(this.model).then((data) => {
				if (data) {
					if (data.acls) {
						this.list = data.acls
					}
					if (data.manageAcls) {
						this.manageAclList = data.manageAcls
					}
					this.inheritedAclsById = data.inheritedAclsById
					this.aclEnabled = data.aclEnabled
					this.aclCanManage = data.aclCanManage
					this.groupFolderId = data.groupFolderId
					this.aclNodePath = data.aclNodePath
					if (!this.aclCanManage) {
						this.list = this.list.filter(item => item.permissions !== 0)
					}
				}
				this.loading = false
				if (this.aclCanManage) {
					this.searchMappings('')
				}
			}).catch(() => {
				this.loading = false
			})
		},
		getFullDisplayName(displayName, type) {
			if (type === 'group') {
				return `${displayName} (${t('groupfolders', 'Group')})`
			}
			if (type === 'circle') {
				return `${displayName} (${t('groupfolders', 'Team')})`
			}

			return displayName
		},
		searchMappings(query) {
			if (searchRequestCancelSource) {
				searchRequestCancelSource.cancel('Operation canceled by another search request.')
			}
			searchRequestCancelSource = axios.CancelToken.source()
			this.isSearching = true
			axios.get(generateUrl(`apps/groupfolders/folders/${this.groupFolderId}/search`) + '?format=json&search=' + query + '&path=' + encodeURIComponent(this.aclNodePath || ''), {
				cancelToken: searchRequestCancelSource.token,
			}).then((result) => {
				this.isSearching = false
				const groups = Object.values(result.data.ocs.data.groups).map((group) => {
					return {
						unique: 'group:' + group.gid,
						type: 'group',
						id: group.gid,
						displayname: group.displayname,
						label: this.getFullDisplayName(group.displayname, 'group'),
					}
				})
				const users = Object.values(result.data.ocs.data.users).map((user) => {
					return {
						unique: 'user:' + user.uid,
						type: 'user',
						id: user.uid,
						displayname: user.displayname,
						label: this.getFullDisplayName(user.displayname, 'user'),
					}
				})
				const circles = Object.values(result.data.ocs.data.circles).map((user) => {
					return {
						unique: 'circle:' + user.sid,
						type: 'circle',
						id: user.sid,
						displayname: user.displayname,
						label: this.getFullDisplayName(user.displayname, 'circle'),
					}
				})
				this.options = [...groups, ...users, ...circles].filter((entry) => {
					return !this.list.find((existingAcl) => entry.unique === existingAcl.getUniqueMappingIdentifier() && existingAcl.permissions !== 0)
				})
			}).catch((error) => {
				if (!axios.isCancel(error)) {
					logger.error('Failed to search results for groupfolder ACL')
				}
			})
		},
		toggleAclCreate() {
			this.showAclCreate = !this.showAclCreate
			if (this.showAclCreate) {
				Vue.nextTick(() => {
					this.$refs.select.$el.querySelector('input').focus()
				})
			}
		},
		async createAcl(option) {
			this.value = null
			const existingIndex = this.list.findIndex(item => item.mappingType === option.type && item.mappingId === option.id)
			let rule
			if (existingIndex > -1) {
				rule = this.list[existingIndex].clone()
				rule.mask = 0b111111
				rule.permissions = OC.PERMISSION_READ
				rule.inherited = false
				Vue.set(this.list, existingIndex, rule)
			} else {
				rule = new Rule()
				rule.fromValues(option.type, option.id, option.displayname, 0b111111, OC.PERMISSION_READ)
				this.list.push(rule)
			}
			try {
				await client.propPatchRuleOperation(this.model, rule, 'add')
				this.showAclCreate = false
			} finally {
				this.loadAcls()
			}
		},
		async removeAcl(rule) {
			const index = this.list.indexOf(rule)
			
			if (index > -1) {
				if (rule.inherited) {
					const newRule = rule.clone()
					newRule.inherited = false
					newRule.mask = 63
					newRule.permissions = 0
					Vue.set(this.list, index, newRule)
					try {
						await client.propPatchRuleOperation(this.model, newRule, 'update')
					} catch (error) {
						Vue.set(this.list, index, rule)
						showError(error.message || t('groupfolders', 'Failed to remove inherited permission'))
					} finally {
						this.loadAcls()
					}
				} else {
					try {
						await client.propPatchRuleOperation(this.model, rule, 'delete')
						this.list.splice(index, 1)
						this.aclCanManage = this.currentUserEffectivePermission > 0 && (this.currentUserEffectivePermission & 32) !== 0
					} catch (error) {
						showError(error.message || t('groupfolders', 'Failed to remove permission'))
					} finally {
						this.loadAcls()
					}
				}
			}
		},
		startEditing(item) {
			this.editingItemId = item.mappingId
			Vue.nextTick(() => {
				const select = this.$refs.permissionSelect
				if (select) {
					select.$el.querySelector('input').focus()
				}
			})
		},
		stopEditing() {
			this.editingItemId = null
		},
		async changePermission(item, option) {
			if (!option || !option.value) {
				this.stopEditing()
				return
			}
			
			const index = this.list.indexOf(item)
			const itemRestorePoint = item.clone()
			item = item.clone()
			
			if (option.value === 'read') {
				item.mask = 0b111111
				item.permissions = OC.PERMISSION_READ
			} else if (option.value === 'edit') {
				const EDIT_PERMS = OC.PERMISSION_UPDATE | OC.PERMISSION_CREATE | OC.PERMISSION_DELETE
				item.mask = 0b111111
				item.permissions = OC.PERMISSION_READ | EDIT_PERMS
			} else if (option.value === 'manage') {
				const EDIT_PERMS = OC.PERMISSION_UPDATE | OC.PERMISSION_CREATE | OC.PERMISSION_DELETE
				item.mask = 0b111111
				item.permissions = OC.PERMISSION_READ | EDIT_PERMS | PERMISSION_MANAGE_ACL
			}
			
			item.inherited = false
			Vue.set(this.list, index, item)
			this.loading = true
			try {
				await client.propPatchRuleOperation(this.model, item, 'update')
			} catch (error) {
				Vue.set(this.list, index, itemRestorePoint)
				showError(error.message || t('groupfolders', 'Failed to update permission'))
			} finally {
				this.loadAcls()
				this.stopEditing()
			}
		},

	},
}
</script>

<style scoped>
	#groupfolder-acl-container {
		margin-top: -28px;
	}

	.groupfolder-entry {
		height: 44px;
		white-space: normal;
		display: inline-flex;
		align-items: center;
		position: relative;
	}

	.avatar.icon-group-white {
		display: inline-block;
		background-color: var(--color-primary-element, #0082c9);
		padding: 16px;
	}

	.groupfolder-entry .username {
		padding: 0 8px;
		overflow: hidden;
		white-space: nowrap;
		text-overflow: ellipsis;
	}

	table {
		width: 100%;
		margin-top: -44px;
		margin-bottom: 5px;
	}

	table td, table th {
		padding: 0
	}

	thead th {
		height: 44px;
	}

	thead th:first-child,
	tbody tr td:first-child {
		width: 24px;
		padding: 0;
		padding-left: 4px;
	}

	table .avatardiv {
		margin-top: 6px;
	}

	table thead th:nth-child(2),
	table .username {
		padding-left: 13px;
		text-overflow: ellipsis;
		overflow: hidden;
		max-width: 0;
		min-width: 50px;
	}

	.permissions-column {
		width: 120px !important;
		padding: 3px;
		cursor: pointer;
	}

	.permission-text {
		display: block;
		padding: 6px 10px;
		border-radius: var(--border-radius-large);
	}

	.permission-text:hover {
		background-color: var(--color-background-hover);
	}

	/* 权限下拉框样式 */
	.permission-select {
		width: 142px !important;
		max-width: 142px !important;
		min-width: 142px !important;
	}

	/* 权限下拉框激活状态 */
	.permission-select.is-open {
		width: 142px !important;
	}

	/* 权限下拉框内容弹出层 - 针对挂载到 body 的情况 */
	.vs__dropdown-menu {
		width: 142px !important;
		min-width: 142px !important;
		max-width: 142px !important;
		box-sizing: border-box !important;
	}

	/* 权限下拉框选项 */
	.vs__dropdown-option {
		width: 100% !important;
		box-sizing: border-box !important;
		padding: 0 8px !important;
	}

	.state-column {
		text-align: center;
		width: 44px !important;
		padding: 3px;
	}

	thead .state-column {
		text-overflow: ellipsis;
		overflow: hidden;
	}

	table button {
		height: 26px;
		width: 24px !important;
		display: block;
		border-radius: 50%;
		margin: auto;
	}

	a.icon-close {
		display: inline-block;
		height: 24px;
		width: 100%;
		vertical-align: middle;
		background-size: 12px;
		opacity: .7;
		float: right;
	}

	a.icon-close:hover {
		opacity: 1;
	}

	.multiselect {
		margin-left: 44px;
		width: calc(100% - 44px);
	}

	.acl-add-row {
		min-height: 34px;
		margin-bottom: 0;
		display: flex;
		align-items: center;
	}

	/* 普通用户模式下隐藏空白区域 */
	#groupfolder-acl-container:not(.admin-mode) .acl-add-row {
		display: none;
	}

	.acl-select-wrapper {
		display: flex;
		align-items: center;
		gap: 4px;
		width: 100%;
	}

	.acl-select-wrapper .v-select {
		flex: 1;
	}

	.manage-list-hint {
		padding: 8px 4px;
		margin-bottom: 8px;
		color: var(--color-text-maxcontrast);
		font-size: 12px;
		line-height: 1.4;
	}

	.permission-text.readonly {
		cursor: default;
		color: var(--color-text-maxcontrast);
	}

	.permission-text.readonly:hover {
		background-color: transparent;
	}
</style>