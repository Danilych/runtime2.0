
SERVER_ID = "5ed67d80-9017-4753-9633-685a1926a6b9"

# defaults

DEFAULT_LANGUAGE = "en"
DEFAULT_APPLICATION = None

# server

SERVER_ADDRESS = ""
SERVER_PORT = 80

# locations

REPOSITORY_LOCATION = "../repository"
TYPES_LOCATION = "../types"
APPLICATIONS_LOCATION = "../applications"
RESOURCES_LOCATION = "../resources"
CACHE_LOCATION = "../cache"
DATA_LOCATION = "../data"
TEMPORARY_LOCATION = "../temp"

# other locations

DATABASES_LOCATION = DATA_LOCATION + "/databases"
STORAGE_LOCATION = DATA_LOCATION + "/storage"
LOGS_LOCATION = DATA_LOCATION
INDEX_LOCATION = DATA_LOCATION + "/memory.index"

SERVER_PIDFILE_LOCATION = TEMPORARY_LOCATION + "/server.pid"
LOGGER_PIDFILE_LOCATION = TEMPORARY_LOCATION + "/logger.pid"

# obsolete locations

# LOCAL_LOCATION = "../local"
# MODULES_LOCATION = LOCAL_LOCATION + "/modules"
# LIBRARIES_LOCATION = LOCAL_LOCATION + "/libraries"

FONTS_LOCATION = "../fonts"

# memory

APPLICATION_FILENAME = "application.xml"
TYPE_FILENAME = "type.xml"
APPLICATION_LIBRARIES_DIRECTORY = "libraries"
TYPE_MODULE_NAME = "type"
REPOSITORY_TYPES_DIRECTORY = "types"
RESOURCE_LINE_LENGTH = 76
STORE_DEFAULT_VALUES = False
PRELOAD_DEFAULT_APPLICATION = False

# autosave

ALLOW_TO_CHANGE = None  # "00000000-0000-0000-0000-000000000000", ...
AUTOSAVE_APPLICATIONS = True

# sessions

SESSION_LIFETIME = 1200

# timeouts

SCRIPT_TIMEOUT = 30.1
COMPUTE_TIMEOUT = 30.1
RENDER_TIMEOUT = 30.1
WYSIWYG_TIMEOUT = 30.1

# threading

QUANTUM = 0.5
COUNTDOWN = 3.0
MAIN_NAME = "Main"

# logging

LOGGER = "native"  # "native", "ovh"
START_LOG_SERVER = True

LOG_LEVEL = 0  # 0 (DEBUG), 1 (MESSAGE), 2 (WARNING), 3 (ERROR)
CONSOLE_LOG_LEVEL = 0

LOGGING_ADDRESS = "127.0.0.1"
LOGGING_PORT = 1010

OVH_LOGGING_ADDRESS = "discover.logs.ovh.com"
OVH_LOGGING_PORT = 12202  # 2201 (LTSV TCP), 2202 (GELF TCP), 12201 (LTSV TLS), 12202 (GELF TLS)
OVH_LOGGING_ENGINE = "gelf"  # "gelf", "ltsv"
OVH_LOGGING_TLS = True
OVH_LOGGING_TOKEN = "3d01766a-bdf1-4e20-83bc-1e4cf812e3a5"

LOGGING_TIMESTAMP = "%Y-%m-%d %H:%M:%S"
DISCOVER_LOGGING_MODULE = True
LOGGING_OUTPUT = True

if MANAGE:
    LOGGER = None
    LOG_LEVEL = 2

# profiling

PROFILING = False
PROFILING_SAVE_PERIODICITY = 5.0
PROFILE_FILENAME = "server.prs"
PROFILE_LOCATION = DATA_LOCATION + "/" + PROFILE_FILENAME

# scripting

STORE_BYTECODE = False

# watcher

WATCHER = True
WATCHER_ADDRESS = "127.0.0.1"
WATCHER_PORT = 1011

# vscript

DISABLE_VSCRIPT = 0
OPTIMIZE_VSCRIPT_PARSER = 0
SHOW_VSCRIPT_LISTING = False

# emails

SMTP_SENDMAIL_TIMEOUT = 20.0
SMTP_SERVER_ADDRESS = ""
SMTP_SERVER_PORT = 25
SMTP_SERVER_USER = ""
SMTP_SERVER_PASSWORD = ""

# licensing

PRELICENSE = {}
