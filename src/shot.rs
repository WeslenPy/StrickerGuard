//! `--screenshot <file.png>`: saves the window's picture through WebView2's
//! own capture (works even when the window is covered) and quits.

use std::path::PathBuf;
use tauri::{AppHandle, Manager};

pub fn capture_and_exit(app: AppHandle, out: PathBuf) {
    let Some(win) = app.get_webview_window("main") else {
        app.exit(2);
        return;
    };
    let app2 = app.clone();
    let res = win.with_webview(move |wv| {
        #[cfg(windows)]
        unsafe {
            if let Err(e) = capture_windows(wv, out.clone(), app2.clone()) {
                eprintln!("captura falhou: {e}");
                app2.exit(3);
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (wv, &out);
            app2.exit(4);
        }
    });
    if res.is_err() {
        app.exit(2);
    }
}

#[cfg(windows)]
unsafe fn capture_windows(wv: tauri::webview::PlatformWebview, out: PathBuf, app: AppHandle) -> windows::core::Result<()> {
    use webview2_com::CapturePreviewCompletedHandler;
    use webview2_com::Microsoft::Web::WebView2::Win32::COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG;
    use windows::Win32::System::Com::{IStream, STATFLAG_NONAME, STATSTG, STREAM_SEEK_SET};
    use windows::Win32::UI::Shell::SHCreateMemStream;

    let core = wv.controller().CoreWebView2()?;
    let stream: IStream = SHCreateMemStream(None).ok_or_else(windows::core::Error::empty)?;
    let s2 = stream.clone();
    let handler = CapturePreviewCompletedHandler::create(Box::new(move |result| {
        let code = (|| -> windows::core::Result<()> {
            result?;
            s2.Seek(0, STREAM_SEEK_SET, None)?;
            let mut stat = STATSTG::default();
            s2.Stat(&mut stat, STATFLAG_NONAME)?;
            let mut buf = vec![0u8; stat.cbSize as usize];
            let mut read = 0u32;
            let _ = s2.Read(buf.as_mut_ptr() as *mut _, buf.len() as u32, Some(&mut read));
            buf.truncate(read as usize);
            if let Some(p) = out.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            std::fs::write(&out, &buf).map_err(|_| windows::core::Error::empty())?;
            Ok(())
        })();
        app.exit(if code.is_ok() { 0 } else { 5 });
        Ok(())
    }));
    core.CapturePreview(COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG, &stream, &handler)?;
    Ok(())
}
