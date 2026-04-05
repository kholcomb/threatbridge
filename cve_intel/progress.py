"""Progress feedback protocol for long-running operations.

The pipeline and fetchers accept a ProgressContext so they can report
status without coupling library code to Rich or any specific display backend.
The CLI wires in RichProgress; MCP server and tests get NullProgress (no-op).
"""

from __future__ import annotations

from typing import Callable, Protocol


class ProgressContext(Protocol):
    """Minimal interface for reporting pipeline progress."""

    def advance(self, stage_name: str) -> None:
        """Called at the start of each named stage."""
        ...

    def set_description(self, text: str) -> None:
        """Update the current description (e.g. 'Calling Claude…')."""
        ...

    def download_callback(self) -> Callable[[int, int], None] | None:
        """Return a (bytes_written, total_bytes) callback, or None."""
        ...


class NullProgress:
    """No-op progress context — used in MCP server and tests."""

    def advance(self, stage_name: str) -> None:
        pass

    def set_description(self, text: str) -> None:
        pass

    def download_callback(self) -> Callable[[int, int], None] | None:
        return None


class RichProgress:
    """Rich-backed progress context for CLI use."""

    def __init__(self) -> None:
        from rich.progress import (
            BarColumn,
            DownloadColumn,
            Progress,
            SpinnerColumn,
            TextColumn,
            TimeElapsedColumn,
            TransferSpeedColumn,
        )
        from rich.console import Console

        self._console = Console(stderr=True)
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeElapsedColumn(),
            console=self._console,
            transient=True,
        )
        self._stage_task = None
        self._download_task = None

    def start(self) -> None:
        self._progress.start()
        self._stage_task = self._progress.add_task("[cyan]Starting…", total=None)

    def stop(self) -> None:
        self._progress.stop()

    def advance(self, stage_name: str) -> None:
        if self._stage_task is not None:
            self._progress.update(
                self._stage_task,
                description=f"[cyan]{stage_name}",
            )

    def set_description(self, text: str) -> None:
        if self._stage_task is not None:
            self._progress.update(self._stage_task, description=f"[yellow]{text}")

    def download_callback(self) -> Callable[[int, int], None] | None:
        """Return a callback that drives a download progress bar."""

        def _cb(bytes_written: int, total_bytes: int) -> None:
            if self._download_task is None:
                self._download_task = self._progress.add_task(
                    "[cyan]Downloading ATT&CK bundle (~80 MB)…",
                    total=total_bytes if total_bytes > 0 else None,
                )
            self._progress.update(self._download_task, completed=bytes_written)

        return _cb
