SERVER_ID = "5ed67d80-9017-4753-9633-685a1926a6b9"

# defaults

DEFAULT_LANGUAGE = "en"
DEFAULT_APPLICATION = None

# server

SERVER_ADDRESS = ""
SERVER_PORT = 8000

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
INDEX_LOCATION = DATA_LOCATION + "/memory.index"  # memory type index

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
RESOURCE_LINE_LENGTH = 76  # line length for stored resources
STORE_DEFAULT_VALUES = False  # store default attribute values on disk
PRELOAD_DEFAULT_APPLICATION = False  # preload default application on start
MANUAL_GARBAGE_COLLECTING = False  # collect garbage on server idle instead auto
BINARY_LOADS_EXTENSION = True  # use binary memory.vdomxml.loads if available

# compiler

SHOW_PAGE_LISTING = False  # show compiler page listing for debugging
ENABLE_STATIC_WYSIWYG = False  # allow to embed static wysiwyg into objects

# autosave

ALLOW_TO_CHANGE = None  # "00000000-0000-0000-0000-000000000000", ...
AUTOSAVE_APPLICATIONS = True  # periodically save application

# sessions

SESSION_LIFETIME = 1200  # life time for web sessions

# timeouts

SCRIPT_TIMEOUT = 30.1  # default termination timeout for arbitrary actions
COMPUTE_TIMEOUT = 30.1  # cumulutive timeout for all comupter actions
RENDER_TIMEOUT = 30.1  # cumulative timeout for all onload actions
WYSIWYG_TIMEOUT = 30.1  # cumulative timeout fro all wysiwyg actinos

CONNECTION_INITIAL_TIMEOUT = 3.0  # initial connection timeout before disconnect
CONNECTION_SUBSEQUENT_TIMEOUT = 30.0  # connection timeout after receive any data

# threading

QUANTUM = 0.5  # default idle quantum for smart threads
COUNTDOWN = 3.0  # left for compatibility...
MAIN_NAME = "Main"  # main thread name

# logging

LOGGER = "native"  # "native", "ovh"
START_LOG_SERVER = True  # start log server in case of native logger

LOG_LEVEL = 0  # 0 (DEBUG), 1 (MESSAGE), 2 (WARNING), 3 (ERROR), can change at runtime
CONSOLE_LOG_LEVEL = 0  # separate log level for console output

DETAILED_LOGGING = False  # log elementary operations, can change at runtime

LOGGING_ADDRESS = "127.0.0.1"
LOGGING_PORT = 10100

OVH_LOGGING_ADDRESS = "discover.logs.ovh.com"
OVH_LOGGING_PORT = 12202  # 2201 (LTSV TCP), 2202 (GELF TCP), 12201 (LTSV TLS), 12202 (GELF TLS)
OVH_LOGGING_ENGINE = "gelf"  # "gelf", "ltsv"
OVH_LOGGING_TLS = True
OVH_LOGGING_TOKEN = "3d01766a-bdf1-4e20-83bc-1e4cf812e3a5"

LOGGING_TIMESTAMP = "%Y-%m-%d %H:%M:%S"
DISCOVER_LOGGING_MODULE = True  # discover calling module for logging
LOGGING_OUTPUT = True  # log all standard and error outputs
LOGGING_INDENT = "    "

if MANAGE:  # override logging settings for manage utility
    LOGGER = None
    LOG_LEVEL = 2
    CONSOLE_LOG_LEVEL = 1

# profiling

PROFILING = False  # can change at runtime
PROFILING_SAVE_PERIODICITY = 5.0  # interval to save profiling
PROFILE_DEFAULT_NAME = "server"  # profile name for engine tasks
PROFILE_TASKS_NAME = "tasks"  # profile name for background tasks
PROFILE_LOCATION = DATA_LOCATION
PROFILE_EXTENSION = "prs"
PROFILE_FILENAME_TEMPLATE = PROFILE_LOCATION + "/%s." + PROFILE_EXTENSION

# scripting

STORE_BYTECODE = False  # store executables bytecode on disk
STORE_ACTIONS_BYTECODE = False  # store action bytecode on disk
ANALYZE_SCRIPT_STRUCTURE = True  # analyze actions to collect dependencies

# watcher

WATCHER = True
WATCHER_ADDRESS = "127.0.0.1"
WATCHER_PORT = 10110
MONITOR = None  # monitor running threads for debugging
WATCHER_SNAPSHOT_INTERVAL = 5.0  # interval to refresh snapshot for memorize

# vscript

DISABLE_VSCRIPT = 0
OPTIMIZE_VSCRIPT_PARSER = 0  # enable optimization for lexer and parser
SHOW_VSCRIPT_LISTING = False  # show listing on compilation for debugging
ENABLE_PYTHON_INLINES = False  # allow python inline with apostroph for debugging
ENABLE_VSCRIPT_PRECOMPILE = True  # precompile all scripts on start
VSCRIPT_AUTO_PRECOMPILE = True  # precompile dependencies when needed

# soap

AUTOSELECT_NEW_APPLICATION = True  # auto-select new application on create

# manage

MANAGE_LINE_WIDTH = 139  # desired console line width
MANAGE_NAME_WIDTH = 36  # desired width for names and captions
MANAGE_LONG_NAME_WIDTH = 85  # desired width for long list lines

# building

TREAT_WARNINGS_AS_ERRORS = False  # treat warnings as errors when building extensions

# debugging

SHOW_PAGE_DEBUG = True  # can change at runtime
SHOW_TRACKED_PRIMARIES = False  # log trached primaries for debugging

# emails

SMTP_SENDMAIL_TIMEOUT = 20.0
SMTP_SERVER_ADDRESS = ""
SMTP_SERVER_PORT = 25
SMTP_SERVER_USER = ""
SMTP_SERVER_PASSWORD = ""

# licensing

PRELICENSE = {}
