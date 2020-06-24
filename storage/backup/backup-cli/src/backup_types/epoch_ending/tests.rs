// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    backup_types::epoch_ending::{
        backup::{EpochEndingBackupController, EpochEndingBackupOpt},
        restore::{EpochEndingRestoreController, EpochEndingRestoreOpt},
    },
    storage::{local_fs::LocalFs, BackupStorage},
    utils::{
        backup_service_client::BackupServiceClient,
        test_utils::{tmp_db_empty, tmp_db_with_random_content},
        GlobalBackupOpt,
    },
};
use backup_service::start_backup_service;
use libra_config::utils::get_available_port;
use libra_temppath::TempPath;
use std::sync::Arc;
use tokio::time::Duration;

#[test]
fn end_to_end() {
    let (_src_db_dir, src_db, blocks) = tmp_db_with_random_content();
    let (_tgt_db_dir, tgt_db) = tmp_db_empty();
    let backup_dir = TempPath::new();
    backup_dir.create_as_dir().unwrap();
    let store: Arc<dyn BackupStorage> = Arc::new(LocalFs::new(backup_dir.path().to_path_buf()));

    let port = get_available_port();
    let mut rt = start_backup_service(port, src_db);
    let client = Arc::new(BackupServiceClient::new(port));

    let latest_epoch = blocks.last().unwrap().1.ledger_info().next_block_epoch();
    let manifest_handle = rt
        .block_on(
            EpochEndingBackupController::new(
                EpochEndingBackupOpt {
                    start_epoch: 0,
                    end_epoch: latest_epoch,
                },
                GlobalBackupOpt {
                    max_chunk_size: 1024,
                },
                client,
                Arc::clone(&store),
            )
            .run(),
        )
        .unwrap();

    rt.block_on(
        EpochEndingRestoreController::new(
            EpochEndingRestoreOpt { manifest_handle },
            store,
            Arc::new(tgt_db.get_restore_handler()),
        )
        .run(),
    )
    .unwrap();

    let expected_ledgers_infos = blocks
        .into_iter()
        .map(|(_, li)| li)
        .filter(|li| li.ledger_info().ends_epoch())
        .collect::<Vec<_>>();

    assert_eq!(
        tgt_db
            .get_epoch_ending_ledger_infos(0, latest_epoch)
            .unwrap()
            .0,
        expected_ledgers_infos,
    );

    rt.shutdown_timeout(Duration::from_secs(1));
}
