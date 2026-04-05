"""GraphQL probe plugin — introspection query detection."""
from __future__ import annotations

import json
import socket

from leetha.probe.base import ServiceProbe
from leetha.probe.connection import ServiceConnection
from leetha.probe.identity import ServiceIdentity

class GraphQLProbePlugin(ServiceProbe):
    name = "graphql"
    protocol = "tcp"
    default_ports = [80, 443]

    INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'

    def identify(self, conn: ServiceConnection) -> ServiceIdentity | None:
        try:
            # Send HTTP POST with GraphQL introspection query
            body = self.INTROSPECTION_QUERY
            request = (
                f"POST /graphql HTTP/1.1\r\n"
                f"Host: {conn.host}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Accept: application/json\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )
            conn.write(request.encode("utf-8"))
            data = conn.read(8192)
            if not data:
                return None

            text = data.decode("utf-8", errors="replace")

            # Must be an HTTP response
            if not text.startswith("HTTP/"):
                return None

            metadata = {}
            version = None

            # Extract the JSON body
            body_start = text.find("\r\n\r\n")
            if body_start < 0:
                return None

            response_body = text[body_start + 4:]

            # Handle chunked transfer encoding
            # Simple approach: strip chunk size markers
            if "transfer-encoding: chunked" in text[:body_start].lower():
                # Remove chunk markers
                lines = response_body.split("\r\n")
                body_parts = []
                i = 0
                while i < len(lines):
                    # Try to parse as hex chunk size
                    try:
                        chunk_size = int(lines[i].strip(), 16)
                        if chunk_size == 0:
                            break
                        i += 1
                        if i < len(lines):
                            body_parts.append(lines[i])
                        i += 1
                    except ValueError:
                        body_parts.append(lines[i])
                        i += 1
                response_body = "".join(body_parts)

            # Parse JSON response
            try:
                result = json.loads(response_body)
            except (json.JSONDecodeError, ValueError):
                return None

            if not isinstance(result, dict):
                return None

            # Check for GraphQL introspection response structure
            is_graphql = False

            if "data" in result and "__schema" in (result.get("data") or {}):
                is_graphql = True
                schema = result["data"]["__schema"]
                if "types" in schema:
                    type_names = [
                        t.get("name") for t in schema["types"]
                        if isinstance(t, dict) and t.get("name")
                    ]
                    metadata["type_count"] = len(type_names)
                    # Store first few types for identification
                    metadata["types_sample"] = type_names[:10]

            # Also detect GraphQL by error response with expected structure
            if not is_graphql and "errors" in result:
                errors = result["errors"]
                if isinstance(errors, list) and len(errors) > 0:
                    # GraphQL errors have a message field
                    first_err = errors[0]
                    if isinstance(first_err, dict) and "message" in first_err:
                        is_graphql = True
                        metadata["introspection_disabled"] = True
                        metadata["error_message"] = first_err["message"]

            if not is_graphql:
                return None

            # Parse headers for server info
            header_section = text[:body_start]
            for line in header_section.split("\r\n")[1:]:
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key_lower = key.strip().lower()
                val = val.strip()
                if key_lower == "server":
                    version = val
                    metadata["server"] = val

            return ServiceIdentity(
                service="graphql",
                certainty=90,
                version=version,
                metadata=metadata,
            )
        except (socket.timeout, OSError):
            return None
