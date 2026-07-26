fn main() {
    #[cfg(windows)]
    {
        let attrs = tauri_build::Attributes::new().windows_attributes(
            tauri_build::WindowsAttributes::new_without_app_manifest()
                .app_manifest(include_str!("windows/app.manifest")),
        );
        tauri_build::try_build(attrs).expect("failed to run tauri-build with the admin manifest");
    }
    #[cfg(not(windows))]
    {
        tauri_build::build();
    }
}
