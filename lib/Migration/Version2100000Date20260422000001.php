<?php

declare(strict_types=1);

namespace OCA\GroupFolders\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

class Version2100000Date20260422000001 extends SimpleMigrationStep {
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		if (!$schema->hasTable('group_folders_file_acl')) {
			$table = $schema->createTable('group_folders_file_acl');
			$table->addColumn('id', 'bigint', [
				'autoincrement' => true,
				'notnull' => true,
			]);
			$table->addColumn('folder_id', 'bigint', [
				'notnull' => true,
			]);
			$table->addColumn('file_id', 'bigint', [
				'notnull' => true,
			]);
			$table->addColumn('file_path', 'string', [
				'notnull' => true,
				'length' => 4000,
			]);
			$table->addColumn('mapping_type', 'string', [
				'notnull' => true,
				'length' => 16,
			]);
			$table->addColumn('mapping_id', 'string', [
				'notnull' => true,
				'length' => 64,
			]);
			$table->addColumn('permissions', 'smallint', [
				'notnull' => true,
				'default' => 1,
			]);

			$table->setPrimaryKey(['id']);
			$table->addUniqueIndex(['file_id', 'mapping_type', 'mapping_id'], 'groups_folder_file_acl_unique');
			$table->addIndex(['folder_id', 'mapping_type', 'mapping_id'], 'groups_folder_file_acl_folder_mapping');
			$table->addIndex(['folder_id', 'file_path'], 'groups_folder_file_acl_path');
		}

		return $schema;
	}
}
