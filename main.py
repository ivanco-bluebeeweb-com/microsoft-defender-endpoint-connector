"""Microsoft Defender for Endpoint Connector entrypoint."""
from __future__ import annotations

import handlers_connection  # noqa: F401
import handlers_machines  # noqa: F401
import handlers_alerts  # noqa: F401
import handlers_indicators_hunting  # noqa: F401
import handlers_audit  # noqa: F401
import panels  # noqa: F401
import panels_center  # noqa: F401
import panels_settings  # noqa: F401
from app import ext, chat  # noqa: F401

extension = ext
