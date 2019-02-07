# print everything to the console
DEBUG_MODE = 0

# Timeout for z3 (symbolic execution) in ms
TIMEOUT = 1000

# timeout to run symbolic execution (in secs)
GLOBAL_TIMEOUT = 50

# Redirect results to a json file.
STORE_RESULT = 0

# depth limit for DFS
DEPTH_LIMIT = 50

GAS_LIMIT = 4000000

LOOP_LIMIT = 10

# Use a public blockchain to speed up the symbolic execution
USE_GLOBAL_BLOCKCHAIN = 0

# Take state data from state.json to speed up the symbolic execution
INPUT_STATE = 0

# CFG = 1 means that we create a control flow graph and store it as .dot file
CFG = 0

# Directory to store json result files
RESULTS_DIR = "results/"

# Analyze bytecode or source code (default is source code = 0)
BYTECODE = 0
