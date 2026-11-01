import { invoke } from "@tauri-apps/api/core";

export function isTauri(): boolean {
  return (
    typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
  );
}

/** Open a URL in the user's default browser (`cmd /C start` in Tauri,
    new tab in plain browser dev mode). */
export async function openInBrowser(url: string): Promise<void> {
  if (isTauri()) {
    await invoke("open_external", { url });
  } else {
    window.open(url, "_blank");
  }
}
