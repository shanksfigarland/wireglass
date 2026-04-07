from __future__ import annotations

import argparse
import json
import mimetypes
import pathlib
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from generate_sample_pcap import generate_capture_set
from triage_core import CaptureFormatError, analyze_capture_bytes


BASE_DIR = pathlib.Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
SAMPLES_DIR = BASE_DIR / "samples"
MAX_UPLOAD_BYTES = 96 * 1024 * 1024


class TriageRequestHandler(BaseHTTPRequestHandler):
    server_version = "Wireglass/1.0"

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._serve_static("index.html")
            return
        if parsed.path.startswith("/static/"):
            self._serve_static(parsed.path.removeprefix("/static/"))
            return
        if parsed.path == "/api/health":
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "wireglass"})
            return
        if parsed.path == "/api/sample-report":
            self._handle_sample_report()
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Route not found."})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/analyze":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Route not found."})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Upload body was empty."})
            return
        if content_length > MAX_UPLOAD_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"ok": False, "error": f"Upload exceeded the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit."},
            )
            return

        data = self.rfile.read(content_length)
        query = urllib.parse.parse_qs(parsed.query)
        filename = query.get("filename", ["uploaded_capture"])[0]

        try:
            external_lookup_config = self._read_external_lookup_config()
            report = analyze_capture_bytes(data, source_name=filename, external_lookup_config=external_lookup_config)
        except CaptureFormatError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        except Exception as exc:  # pragma: no cover - last-resort handler for local tool UX
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"Unexpected error: {exc}"})
            return

        self._send_json(HTTPStatus.OK, {"ok": True, "report": report})

    def log_message(self, format: str, *args) -> None:
        return

    def _handle_sample_report(self) -> None:
        try:
            outputs = generate_capture_set(SAMPLES_DIR)
            sample_path = outputs["pcapng"]
            report = analyze_capture_bytes(
                sample_path.read_bytes(),
                source_name=sample_path.name,
                external_lookup_config=self._read_external_lookup_config(),
            )
        except CaptureFormatError as exc:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        self._send_json(HTTPStatus.OK, {"ok": True, "report": report})

    def _read_external_lookup_config(self) -> dict[str, object] | None:
        raw = self.headers.get("X-Wireglass-External-Config", "").strip()
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CaptureFormatError(f"External lookup config was invalid JSON: {exc.msg}") from exc
        if not isinstance(parsed, dict):
            raise CaptureFormatError("External lookup config must be a JSON object.")
        return parsed

    def _serve_static(self, relative_path: str) -> None:
        safe_relative = pathlib.Path(relative_path).as_posix().lstrip("/")
        target_path = (STATIC_DIR / safe_relative).resolve()
        if STATIC_DIR.resolve() not in target_path.parents and target_path != STATIC_DIR.resolve():
            self._send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Invalid static path."})
            return
        if not target_path.exists() or not target_path.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Static file not found."})
            return
        content_type, _ = mimetypes.guess_type(str(target_path))
        self._send_bytes(HTTPStatus.OK, target_path.read_bytes(), content_type or "application/octet-stream")

    def _send_json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        self._send_bytes(status, json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8")

    def _send_bytes(self, status: HTTPStatus, data: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(data)


def run_server(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), TriageRequestHandler)
    print(f"Wireglass listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local Wireglass PCAP analysis web app.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    run_server(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
