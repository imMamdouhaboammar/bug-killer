use crate::deepsec::types::*;
use chrono::{DateTime, Utc};
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

pub struct StorageManager {
    base_dir: PathBuf,
}

impl StorageManager {
    fn valid_project_id(project_id: &str) -> bool {
        (1..=128).contains(&project_id.len())
            && project_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    }

    fn valid_relative_path(path: &str) -> bool {
        !path.is_empty()
            && !path.contains('\\')
            && Path::new(path)
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
    }

    fn invalid_input(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, message)
    }

    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            base_dir: root.as_ref().join(".deepsec").join("data"),
        }
    }

    pub fn with_custom_dir(dir: PathBuf) -> Self {
        Self { base_dir: dir }
    }

    pub fn project_dir(&self, project_id: &str) -> PathBuf {
        self.base_dir.join(project_id)
    }

    pub fn files_dir(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("files")
    }

    pub fn runs_dir(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("runs")
    }

    pub fn setup_dir(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("setup")
    }

    pub fn reports_dir(&self, project_id: &str) -> PathBuf {
        self.project_dir(project_id).join("reports")
    }

    pub fn ensure_project(&self, project_id: &str, root_path: &str) -> io::Result<ProjectConfig> {
        if !Self::valid_project_id(project_id) {
            return Err(Self::invalid_input("unsafe project ID"));
        }
        let pdir = self.project_dir(project_id);
        fs::create_dir_all(&pdir)?;
        fs::create_dir_all(self.files_dir(project_id))?;
        fs::create_dir_all(self.runs_dir(project_id))?;
        fs::create_dir_all(self.setup_dir(project_id))?;
        fs::create_dir_all(self.reports_dir(project_id))?;

        let config_path = pdir.join("project.json");
        if config_path.exists() {
            let data = fs::read_to_string(&config_path)?;
            if let Ok(config) = serde_json::from_str::<ProjectConfig>(&data) {
                return Ok(config);
            }
        }

        let config = ProjectConfig {
            project_id: project_id.to_string(),
            root_path: root_path.to_string(),
            created_at: Utc::now().to_rfc3339(),
            github_url: None,
        };
        self.write_atomic(&config_path, &serde_json::to_vec_pretty(&config)?)?;
        Ok(config)
    }

    pub fn file_record_path(&self, project_id: &str, rel_path: &str) -> PathBuf {
        let safe_rel = rel_path.trim_start_matches('/');
        self.files_dir(project_id)
            .join(format!("{}.json", safe_rel))
    }

    pub fn read_file_record(&self, project_id: &str, rel_path: &str) -> Option<FileRecord> {
        if !Self::valid_project_id(project_id) || !Self::valid_relative_path(rel_path) {
            return None;
        }
        let path = self.file_record_path(project_id, rel_path);
        if !path.exists() {
            return None;
        }
        let data = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    pub fn write_file_record(&self, record: &FileRecord) -> io::Result<()> {
        if !Self::valid_project_id(&record.project_id)
            || !Self::valid_relative_path(&record.file_path)
        {
            return Err(Self::invalid_input("unsafe file record path"));
        }
        let path = self.file_record_path(&record.project_id, &record.file_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(record)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.write_atomic(&path, &bytes)
    }

    pub fn load_all_file_records(&self, project_id: &str) -> Vec<FileRecord> {
        if !Self::valid_project_id(project_id) {
            return Vec::new();
        }
        let files_dir = self.files_dir(project_id);
        if !files_dir.exists() {
            return Vec::new();
        }

        let mut records = Vec::new();
        for entry in walkdir::WalkDir::new(&files_dir)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("json")
            {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    if let Ok(rec) = serde_json::from_str::<FileRecord>(&content) {
                        records.push(rec);
                    }
                }
            }
        }
        records
    }

    pub fn write_run_meta(&self, meta: &RunMeta) -> io::Result<()> {
        if !Self::valid_project_id(&meta.project_id) || !Self::valid_project_id(&meta.run_id) {
            return Err(Self::invalid_input("unsafe run metadata path"));
        }
        let path = self
            .runs_dir(&meta.project_id)
            .join(format!("{}.json", meta.run_id));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(meta)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.write_atomic(&path, &bytes)
    }

    pub fn read_run_meta(&self, project_id: &str, run_id: &str) -> Option<RunMeta> {
        if !Self::valid_project_id(project_id) || !Self::valid_project_id(run_id) {
            return None;
        }
        let path = self.runs_dir(project_id).join(format!("{}.json", run_id));
        if !path.exists() {
            return None;
        }
        let data = fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    pub fn is_reclaimable_lock(&self, record: &FileRecord) -> bool {
        if record.locked_by_run_id.is_none() {
            return record.status == FileStatus::Pending;
        }

        if let Some(locked_at_str) = &record.locked_at {
            if let Ok(locked_at) = DateTime::parse_from_rfc3339(locked_at_str) {
                let age = Utc::now().signed_duration_since(locked_at.with_timezone(&Utc));
                if age.num_seconds() > 3600 {
                    return true;
                }
            }
        }

        if let Some(run_id) = &record.locked_by_run_id {
            if let Some(meta) = self.read_run_meta(&record.project_id, run_id) {
                if meta.phase == "done" || meta.phase == "error" {
                    return true;
                }

                let current_host =
                    std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
                if meta.hostname == current_host && meta.pid > 0 {
                    let alive = unsafe { libc::kill(meta.pid as i32, 0) == 0 };
                    if !alive {
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn acquire_file_lock(&self, record: &mut FileRecord, run_id: &str) -> bool {
        if !Self::valid_project_id(&record.project_id)
            || !Self::valid_project_id(run_id)
            || !Self::valid_relative_path(&record.file_path)
        {
            return false;
        }
        let project_id = record.project_id.clone();
        let file_path = record.file_path.clone();
        self.with_file_record_mutex(&project_id, &file_path, || {
            // Always re-read under the mutex. The caller's record may have been
            // loaded before another process acquired the same file.
            let Some(mut latest) = self.read_file_record(&project_id, &file_path) else {
                return Ok(false);
            };
            if !self.is_reclaimable_lock(&latest) {
                return Ok(false);
            }
            latest.status = FileStatus::Processing;
            latest.locked_by_run_id = Some(run_id.to_string());
            latest.locked_at = Some(Utc::now().to_rfc3339());
            self.write_file_record(&latest)?;
            *record = latest;
            Ok(true)
        })
        .unwrap_or(false)
    }

    pub fn release_file_lock(&self, record: &mut FileRecord) -> io::Result<()> {
        if !Self::valid_project_id(&record.project_id)
            || !Self::valid_relative_path(&record.file_path)
        {
            return Err(Self::invalid_input("unsafe file record path"));
        }
        let project_id = record.project_id.clone();
        let file_path = record.file_path.clone();
        self.with_file_record_mutex(&project_id, &file_path, || {
            let mut latest = self
                .read_file_record(&project_id, &file_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "file record missing"))?;
            if latest.locked_by_run_id != record.locked_by_run_id {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "file lock belongs to another run",
                ));
            }
            latest.locked_by_run_id = None;
            latest.locked_at = None;
            self.write_file_record(&latest)?;
            *record = latest;
            Ok(())
        })
    }

    fn with_file_record_mutex<T>(
        &self,
        project_id: &str,
        rel_path: &str,
        operation: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let record_path = self.file_record_path(project_id, rel_path);
        let lock_path = record_path.with_extension("json.lock");
        fs::create_dir_all(lock_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        // Advisory OS mutex across threads and processes; released on close or crash.
        if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let result = operation();
        let unlock_result = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_UN) };
        if unlock_result != 0 && result.is_ok() {
            return Err(io::Error::last_os_error());
        }
        result
    }

    fn write_atomic(&self, path: &Path, content: &[u8]) -> io::Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp_file = tempfile::NamedTempFile::new_in(parent)?;
        io::Write::write_all(&mut temp_file, content)?;
        temp_file.persist(path).map_err(|e| e.error)?;
        Ok(())
    }
}
