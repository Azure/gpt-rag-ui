import re

APPLICATION_INSIGHTS_CONNECTION_STRING = "APPLICATIONINSIGHTS_CONNECTION_STRING"
APP_NAME = "gpt-rag-ui"

# Constants
UUID_REGEX = re.compile(
    r'^\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\s+',
    re.IGNORECASE
)

SUPPORTED_EXTENSIONS = [
    "pdf", "bmp", "jpeg", "jpg", "png", "tiff", "xlsx", "docx", "pptx",
    "md", "txt", "html", "shtml", "htm", "py", "csv", "xml", "json", "vtt"
]

# Href may contain ")" inside the path (e.g. "report (1).pdf"); do not use [^)]+ for the whole URL.
_REFERENCE_URL_BODY = r'[^)]*(?:\([^)]*\)[^)]*)*\.(?:' + '|'.join(SUPPORTED_EXTENSIONS) + r')'
REFERENCE_REGEX = re.compile(
    r'\[([^\]]+)\]\((' + _REFERENCE_URL_BODY + r')\)',
    re.IGNORECASE
)

TERMINATE_TOKEN = "TERMINATE"