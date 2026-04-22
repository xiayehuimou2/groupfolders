/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
import { SyntheticEvent } from 'react'
import * as React from 'react'
import Select from 'react-select'

import './FolderGroups.scss'
import { DelegationCircle, DelegationGroup } from '../types'
import { loadState } from '@nextcloud/initial-state'

function hasPermissions(value: number, check: number): boolean {
	return (value & check) === check
}

export interface FolderGroupsProps {
	groups: { [group: string]: number },
	allCircles?: DelegationCircle[],
	allGroups?: DelegationGroup[],
	onAddGroup: (name: string) => void;
	removeGroup: (name: string) => void;
	edit: boolean;
	showEdit: (event: SyntheticEvent<any>) => void;
	onSetPermissions: (name: string, permissions: number) => void;
}

export function FolderGroups({groups, allGroups = [], allCircles = [], onAddGroup, removeGroup, edit, showEdit, onSetPermissions}: FolderGroupsProps) {
	const isCirclesEnabled = loadState('groupfolders', 'isCirclesEnabled', false)
	const groupHeader = isCirclesEnabled
		? t('groupfolders', 'Group or team')
		: t('groupfolders', 'Group')

	// Format the selected groups with the displayName
	// We try to match a circle, then a group if no match is found,
	// and finally we just use the ID if all previous attempts failed
	const displayNames = Object.keys(groups).map(groupId => {
		return allCircles.find(circle => circle.singleId === groupId)?.displayName
			|| allGroups.find(group => group.gid === groupId)?.displayName
			|| groupId
	})

	if (edit) {
		// Edit permissions: UPDATE + CREATE + DELETE (without SHARE)
		const EDIT_PERMS = OC.PERMISSION_UPDATE | OC.PERMISSION_CREATE | OC.PERMISSION_DELETE;
		const READ_PERM = OC.PERMISSION_READ;
		
		const setPermissions = (change: number, groupId: string, newState: boolean): void => {
			const currentPerms = groups[groupId] || 0;
			let newPermissions: number;
			if (newState) {
				// Checkbox checked: enable edit permissions and always keep READ
				newPermissions = (currentPerms | change) | READ_PERM;
			} else {
				// Checkbox unchecked: disable edit permissions but always keep READ
				newPermissions = (currentPerms & ~change) | READ_PERM;
			}
			onSetPermissions(groupId, newPermissions);
		};

		const rows = Object.keys(groups).map((groupId, index) => {
			const permissions = groups[groupId] || 0;
			// Check if all edit permission bits are set
			const allEditEnabled = (permissions & EDIT_PERMS) === EDIT_PERMS;
			
			return <tr key={groupId}>
				<td>{displayNames[index]}</td>
				<td className="permissions">
					<input type="checkbox"
						   onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPermissions(EDIT_PERMS, groupId, e.target.checked)}
						   checked={allEditEnabled}/>
				</td>
				<td>
					<a onClick={removeGroup.bind(this, groupId)} className="close-btn"></a>
				</td>
			</tr>
		})


		return <table className="group-edit"
				  onClick={event => event.stopPropagation()}>
			<thead>
			<tr>
				<th>{groupHeader}</th>
				<th>{t('groupfolders', 'Edit')}</th>
				<th/>
			</tr>
			</thead>
			<tbody>
			{rows}
			<tr>
				<td colSpan={3}>
					<AdminGroupSelect
						allGroups={allGroups.filter(i => !groups[i.gid])}
						allCircles={allCircles.filter(i => !groups[i.singleId])}
						onChange={onAddGroup}/>
				</td>
			</tr>
			</tbody>
		</table>
	} else {
		if (Object.keys(groups).length === 0) {
			return <span>
				<em>{t('groupfolders', 'None')}</em>
				<a className="icon icon-rename" onClick={showEdit}/>
			</span>
		}

		return <a className="action-rename" onClick={showEdit}>
			{displayNames.join(', ')}
		</a>
	}
}

interface CircleGroupSelectProps {
	allGroups: DelegationGroup[];
	allCircles: DelegationCircle[];
	onChange: (name: string) => void;
}

function AdminGroupSelect({allGroups, allCircles, onChange}: CircleGroupSelectProps) {
	const isCirclesEnabled = loadState('groupfolders', 'isCirclesEnabled', false)
	const emptyGroups = isCirclesEnabled
		? t('groupfolders', 'No other groups or teams available')
		: t('groupfolders', 'No other groups available')

	if (allGroups.length === 0 && allCircles.length === 0) {
		return <div className="no-options-available">
			<p>{emptyGroups}</p>
		</div>
	}
	const groups = allGroups.map(group => {
		return {
			value: group.gid,
			label: group.displayName
		}
	})
	const circles = allCircles.map(circle => {
		return {
			value: circle.singleId,
			label: t('groupfolders', '{displayName} (team)', {...circle})
		}
	})
	const options = [...groups, ...circles]

	const placeholder = isCirclesEnabled
		? t('groupfolders', 'Add group or team')
		: t('groupfolders', 'Add group')

	return <Select
		onChange={option => {
			onChange && option && onChange(option.value)
		}}
		options={options}
		placeholder={placeholder}
		styles={{
			input: (provided) => ({
				...provided,
				height: 30,
				color: 'var(--color-main-text)',
			}),
			control: (provided) => ({
				...provided,
				backgroundColor: 'var(--color-main-background)',
			}),
			menu: (provided) => ({
				...provided,
				backgroundColor: 'var(--color-main-background)',
				borderColor: '#888'
			}),
			option: (provided, state) => ({
				...provided,
				backgroundColor: state.isFocused ? 'var(--color-background-dark)' : 'transparent'
			})
		}}
	/>
}
