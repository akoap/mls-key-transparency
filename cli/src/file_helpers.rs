use std::{fs, env, path::PathBuf};

pub fn get_file_path(file_name: &String) -> PathBuf {
    let tmp_folder = env::temp_dir();
    tmp_folder.join(file_name)
}


pub fn delete_files_with_prefix(prefix: &str) -> Result<(), String> {
    let tmp_dir = env::temp_dir();
    let files = fs::read_dir(tmp_dir).expect("Error reading temp dir.");

    for file in files {
        let file = file.expect(format!("Error getting file in {:?}", prefix).as_str());
        let file_name = file.file_name();
        if let Some(name) = file_name.to_str() {
            if name.starts_with(prefix) {
                fs::remove_file(file.path()).expect(format!("Error deleting file, {:?}", file_name).as_str());
            }
        }
    }

    Ok(())
}
