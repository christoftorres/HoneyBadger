import tokenize
import sha3
from tokenize import NUMBER, NAME, NEWLINE
import re
import math
import sys
import pickle
import json
import traceback
import signal
import time
import logging
import os.path
import z3
import binascii
import global_params

from collections import namedtuple
from vargenerator import *
from ethereum_data_etherscan import *
from basicblock import BasicBlock
from analysis import *

log = logging.getLogger(__name__)

UNSIGNED_BOUND_NUMBER = 2**256 - 1
CONSTANT_ONES_159 = BitVecVal((1 << 160) - 1, 256)

def enum(**named_values):
    return type('Enum', (), named_values)

HeuristicTypes = enum(
    MONEY_FLOW="Money flow",
    BALANCE_DISORDER="Balance disorder",
    HIDDEN_TRANSFER="Hidden transfer",
    INHERITANCE_DISORDER="Inheritance disorder",
    UNINITIALISED_STRUCT="Uninitialised struct",
    TYPE_DEDUCTION_OVERFLOW="Type deduction overflow",
    SKIP_EMPTY_STRING_LITERAL="Skip empty string literal",
    HIDDEN_STATE_UPDATE="Hidden state update",
    STRAW_MAN_CONTRACT="Straw man contract"
)

class Parameter:
    def __init__(self, **kwargs):
        attr_defaults = {
            "instr": "",
            "block": 0,
            "depth": 0,
            "pre_block": 0,
            "func_call": -1,
            "stack": [],
            "calls": [],
            "memory": [],
            "models": [],
            "visited": [],
            "visited_edges": {},
            "mem": {},
            "analysis": {},
            "sha3_list": {},
            "global_state": {},
            "is_feasible": True,
            "path_conditions_and_vars": {}
        }
        for (attr, default) in attr_defaults.iteritems():
            setattr(self, attr, kwargs.get(attr, default))

    def copy(self):
        _kwargs = custom_deepcopy(self.__dict__)
        return Parameter(**_kwargs)

def initGlobalVars():
    global solver
    # Z3 solver
    solver = Solver()
    solver.set("timeout", global_params.TIMEOUT)

    global visited_pcs
    visited_pcs = set()

    global results
    results = {
        "evm_code_coverage": "", "execution_time": "", "dead_code": [],
        "execution_paths": "", "timeout": False, "money_flow": False,
        "balance_disorder": False, "hidden_transfer": False,
        "inheritance_disorder": False, "uninitialised_struct": False,
        "type_deduction_overflow": False, "skip_empty_string_literal": False,
        "hidden_state_update": False, "straw_man_contract": False,
        "attack_methods": [], "cashout_methods": []
    }

    global g_timeout
    g_timeout = False

    global feasible_blocks
    feasible_blocks = []

    global infeasible_blocks
    infeasible_blocks = []

    global execution_paths
    execution_paths = {}

    global list_of_comparisons
    list_of_comparisons = {}

    global list_of_functions
    list_of_functions = {}

    global list_of_structs
    list_of_structs = []

    global list_of_sstores
    list_of_sstores = []

    global list_of_calls
    list_of_calls = {}

    global list_of_suicides
    list_of_suicides = []

    global list_of_vars
    list_of_vars = {}

    global list_of_multiplications
    list_of_multiplications = {}

    global list_of_additions
    list_of_additions = {}

    global terminals
    terminals = []

    global message_value
    message_value = None

    global account_balance
    account_balance = None

    global suicidal
    suicidal = False

    global heuristics
    heuristics = []





    # capturing the last statement of each basic block
    global end_ins_dict
    end_ins_dict = {}

    # capturing all the instructions, keys are corresponding addresses
    global instructions
    instructions = {}

    # capturing the "jump type" of each basic block
    global jump_type
    jump_type = {}

    global vertices
    vertices = {}

    global edges
    edges = {}

    # store the path condition corresponding to each path in money_flow_all_paths
    global path_conditions
    path_conditions = []

    # store global variables, e.g. storage, balance of all paths
    global all_gs
    all_gs = []

    global total_no_of_paths
    total_no_of_paths = 0

    global no_of_test_cases
    no_of_test_cases = 0

    # to generate names for symbolic variables
    global gen
    gen = Generator()

    global data_source
    if global_params.USE_GLOBAL_BLOCKCHAIN:
        data_source = EthereumData()

    global log_file
    log_file = open(c_name + '.log', "w")

def change_format():
    with open(c_name) as disasm_file:
        file_contents = disasm_file.readlines()
        i = 0
        firstLine = file_contents[0].strip('\n')
        for line in file_contents:
            line = line.replace('SELFDESTRUCT', 'SUICIDE')
            line = line.replace('Missing opcode 0xfd', 'REVERT')
            line = line.replace('Missing opcode 0xfe', 'ASSERTFAIL')
            line = line.replace('Missing opcode', 'INVALID')
            line = line.replace(':', '')
            lineParts = line.split(' ')
            try: # removing initial zeroes
                lineParts[0] = str(int(lineParts[0]))

            except:
                lineParts[0] = lineParts[0]
            lineParts[-1] = lineParts[-1].strip('\n')
            try: # adding arrow if last is a number
                lastInt = lineParts[-1]
                if(int(lastInt, 16) or int(lastInt, 16) == 0) and len(lineParts) > 2:
                    lineParts[-1] = "=>"
                    lineParts.append(lastInt)
            except Exception:
                pass
            file_contents[i] = ' '.join(lineParts)
            i = i + 1
        file_contents[0] = firstLine
        file_contents[-1] += '\n'

    with open(c_name, 'w') as disasm_file:
        disasm_file.write("\n".join(file_contents))

def build_cfg_and_analyze():
    global source_map

    change_format()
    with open(c_name, 'r') as disasm_file:
        disasm_file.readline()  # Remove first line
        tokens = tokenize.generate_tokens(disasm_file.readline)
        collect_vertices(tokens)
        construct_bb()
        construct_static_edges()
        full_sym_exec()  # jump targets are constructed on the fly
        if global_params.CFG:
            print_cfg()

def print_cfg():
    f = open(c_name.replace('.disasm', '').replace(':', '-')+'.dot', 'w')
    f.write('digraph honeybadger_cfg {\n')
    f.write('rankdir = TB;\n')
    f.write('size = "240"\n')
    f.write('graph[fontname = Courier, fontsize = 14.0, labeljust = l, nojustify = true];node[shape = record];\n')
    address_width = 10
    if len(hex(instructions.keys()[-1])) > address_width:
        address_width = len(hex(instructions.keys()[-1]))
    for block in vertices.values():
        #block.display()
        address = block.get_start_address()
        label = '"'+hex(block.get_start_address())+'"[label="'
        for instruction in block.get_instructions():
            label += "{0:#0{1}x}".format(address, address_width)+" "+instruction+"\l"
            address += 1 + (len(instruction.split(' ')[1].replace("0x", "")) / 2)
        if block.get_start_address() in infeasible_blocks:
            f.write(label+'",style=filled,color=gray];\n')
        else:
            f.write(label+'"];\n')
        if block.get_block_type() == "conditional":
            if len(edges[block.get_start_address()]) > 1:
                true_branch = block.get_branch_expression()
                if is_expr(true_branch):
                    true_branch = simplify(true_branch)
                f.write('"'+hex(block.get_start_address())+'" -> "'+hex(edges[block.get_start_address()][1])+'" [color="green" label=" '+str(true_branch)+'"];\n')
                false_branch = Not(block.get_branch_expression())
                if is_expr(false_branch):
                    false_branch = simplify(false_branch)
                f.write('"'+hex(block.get_start_address())+'" -> "'+hex(edges[block.get_start_address()][0])+'" [color="red" label=" '+str(false_branch)+'"];\n')
            else:
                f.write('"'+hex(block.get_start_address())+'" -> "UNKNOWN_TARGET" [color="black" label=" UNKNOWN_BRANCH_EXPR"];\n')
                f.write('"'+hex(block.get_start_address())+'" -> "'+hex(edges[block.get_start_address()][0])+'" [color="black"];\n')
        elif block.get_block_type() == "unconditional" or block.get_block_type() == "falls_to":
            if len(edges[block.get_start_address()]) > 0:
                for i in range(len(edges[block.get_start_address()])):
                    f.write('"'+hex(block.get_start_address())+'" -> "'+hex(edges[block.get_start_address()][i])+'" [color="black"];\n')
            else:
                f.write('"'+hex(block.get_start_address())+'" -> "UNKNOWN_TARGET" [color="black"];\n')
    f.write('}\n')
    f.close()
    log.debug(str(edges))

def mapping_push_instruction(current_line_content, current_ins_address, idx, positions, length):
    global source_map

    while (idx < length):
        if not positions[idx]:
            return idx + 1
        name = positions[idx]['name']
        if name.startswith("tag"):
            idx += 1
        else:
            if name.startswith("PUSH"):
                if name == "PUSH":
                    value = positions[idx]['value']
                    instr_value = current_line_content.split(" ")[1]
                    if int(value, 16) == int(instr_value, 16):
                        source_map.instr_positions[current_ins_address] = source_map.positions[idx]
                        idx += 1
                        break;
                    else:
                        raise Exception("Source map error")
                else:
                    source_map.instr_positions[current_ins_address] = source_map.positions[idx]
                    idx += 1
                    break;
            else:
                raise Exception("Source map error")
    return idx

def mapping_non_push_instruction(current_line_content, current_ins_address, idx, positions, length):
    global source_map

    while (idx < length):
        if not positions[idx]:
            return idx + 1
        name = positions[idx]['name']
        if name.startswith("tag"):
            idx += 1
        else:
            instr_name = current_line_content.split(" ")[0]
            if name == instr_name or name == "INVALID" and instr_name == "ASSERTFAIL" or name == "KECCAK256" and instr_name == "SHA3" or name == "SELFDESTRUCT" and instr_name == "SUICIDE":
                source_map.instr_positions[current_ins_address] = source_map.positions[idx]
                idx += 1
                break;
            else:
                raise Exception("Source map error")
    return idx

# 1. Parse the disassembled file
# 2. Then identify each basic block (i.e. one-in, one-out)
# 3. Store them in vertices
def collect_vertices(tokens):
    global source_map
    if source_map:
        idx = 0
        positions = source_map.positions
        length = len(positions)
    global end_ins_dict
    global instructions
    global jump_type

    current_ins_address = 0
    last_ins_address = 0
    is_new_line = True
    current_block = 0
    current_line_content = ""
    wait_for_push = False
    is_new_block = False

    for tok_type, tok_string, (srow, scol), _, line_number in tokens:
        if wait_for_push is True:
            push_val = ""
            for ptok_type, ptok_string, _, _, _ in tokens:
                if ptok_type == NEWLINE:
                    is_new_line = True
                    current_line_content += push_val + ' '
                    instructions[current_ins_address] = current_line_content
                    idx = mapping_push_instruction(current_line_content, current_ins_address, idx, positions, length) if source_map else None
                    log.debug(current_line_content)
                    current_line_content = ""
                    wait_for_push = False
                    break
                try:
                    int(ptok_string, 16)
                    push_val += ptok_string
                except ValueError:
                    pass
            continue
        elif is_new_line is True and tok_type == NUMBER:  # looking for a line number
            last_ins_address = current_ins_address
            try:
                current_ins_address = int(tok_string)
            except ValueError:
                log.critical("ERROR when parsing row %d col %d", srow, scol)
                quit()
            is_new_line = False
            if is_new_block:
                current_block = current_ins_address
                is_new_block = False
            continue
        elif tok_type == NEWLINE:
            is_new_line = True
            log.debug(current_line_content)
            instructions[current_ins_address] = current_line_content
            idx = mapping_non_push_instruction(current_line_content, current_ins_address, idx, positions, length) if source_map else None
            current_line_content = ""
            continue
        elif tok_type == NAME:
            if tok_string == "JUMPDEST":
                if last_ins_address not in end_ins_dict:
                    end_ins_dict[current_block] = last_ins_address
                current_block = current_ins_address
                is_new_block = False
            elif tok_string == "STOP" or tok_string == "RETURN" or tok_string == "SUICIDE" or tok_string == "REVERT" or tok_string == "ASSERTFAIL":
                jump_type[current_block] = "terminal"
                end_ins_dict[current_block] = current_ins_address
            elif tok_string == "JUMP":
                jump_type[current_block] = "unconditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string == "JUMPI":
                jump_type[current_block] = "conditional"
                end_ins_dict[current_block] = current_ins_address
                is_new_block = True
            elif tok_string.startswith('PUSH', 0):
                wait_for_push = True
            is_new_line = False
        if tok_string != "=" and tok_string != ">":
            current_line_content += tok_string + " "

    if current_block not in end_ins_dict:
        log.debug("current block: %d", current_block)
        log.debug("last line: %d", current_ins_address)
        end_ins_dict[current_block] = current_ins_address

    if current_block not in jump_type:
        jump_type[current_block] = "terminal"

    for key in end_ins_dict:
        if key not in jump_type:
            jump_type[key] = "falls_to"


def construct_bb():
    global vertices
    global edges
    sorted_addresses = sorted(instructions.keys())
    size = len(sorted_addresses)
    for key in end_ins_dict:
        end_address = end_ins_dict[key]
        block = BasicBlock(key, end_address)
        if key not in instructions:
            continue
        block.add_instruction(instructions[key])
        i = sorted_addresses.index(key) + 1
        while i < size and sorted_addresses[i] <= end_address:
            block.add_instruction(instructions[sorted_addresses[i]])
            i += 1
        block.set_block_type(jump_type[key])
        vertices[key] = block
        edges[key] = []


def construct_static_edges():
    add_falls_to()  # these edges are static

def add_falls_to():
    global vertices
    global edges
    key_list = sorted(jump_type.keys())
    length = len(key_list)
    for i, key in enumerate(key_list):
        if jump_type[key] != "terminal" and jump_type[key] != "unconditional" and i+1 < length:
            target = key_list[i+1]
            edges[key].append(target)
            vertices[key].set_falls_to(target)

def get_init_global_state(path_conditions_and_vars):
    global message_value

    global_state = {"balance" : {}, "pc": 0}
    init_is = init_ia = deposited_value = sender_address = receiver_address = gas_price = origin = currentCoinbase = currentNumber = currentDifficulty = currentGasLimit = callData = None

    if global_params.INPUT_STATE:
        with open('state.json') as f:
            state = json.loads(f.read())
            if state["Is"]["balance"]:
                init_is = int(state["Is"]["balance"], 16)
            if state["Ia"]["balance"]:
                init_ia = int(state["Ia"]["balance"], 16)
            if state["exec"]["value"]:
                deposited_value = 0
            if state["Is"]["address"]:
                sender_address = int(state["Is"]["address"], 16)
            if state["Ia"]["address"]:
                receiver_address = int(state["Ia"]["address"], 16)
            if state["exec"]["gasPrice"]:
                gas_price = int(state["exec"]["gasPrice"], 16)
            if state["exec"]["origin"]:
                origin = int(state["exec"]["origin"], 16)
            if state["env"]["currentCoinbase"]:
                currentCoinbase = int(state["env"]["currentCoinbase"], 16)
            if state["env"]["currentNumber"]:
                currentNumber = int(state["env"]["currentNumber"], 16)
            if state["env"]["currentDifficulty"]:
                currentDifficulty = int(state["env"]["currentDifficulty"], 16)
            if state["env"]["currentGasLimit"]:
                currentGasLimit = int(state["env"]["currentGasLimit"], 16)

    # for some weird reason these 3 vars are stored in path_conditions instead of global_state
    else:
        sender_address = BitVec("Is", 256)
        receiver_address = BitVec("Ia", 256)
        deposited_value = BitVec("Iv", 256)
        init_is = BitVec("init_Is", 256)
        init_ia = BitVec("init_Ia", 256)

    path_conditions_and_vars["Is"] = sender_address
    path_conditions_and_vars["Ia"] = receiver_address
    path_conditions_and_vars["Iv"] = deposited_value

    message_value = deposited_value

    constraint = (deposited_value >= BitVecVal(0, 256))
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = (init_is >= deposited_value)
    path_conditions_and_vars["path_condition"].append(constraint)
    constraint = (init_ia >= BitVecVal(0, 256))
    path_conditions_and_vars["path_condition"].append(constraint)

    # update the balances of the "caller" and "callee"

    global_state["balance"]["Is"] = (init_is - deposited_value)
    global_state["balance"]["Ia"] = (init_ia + deposited_value)

    if not gas_price:
        new_var_name = gen.gen_gas_price_var()
        gas_price = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = gas_price

    if not origin:
        new_var_name = gen.gen_origin_var()
        origin = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = origin

    if not currentCoinbase:
        new_var_name = "IH_c"
        currentCoinbase = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentCoinbase

    if not currentNumber:
        new_var_name = "IH_i"
        currentNumber = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentNumber

    if not currentDifficulty:
        new_var_name = "IH_d"
        currentDifficulty = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentDifficulty

    if not currentGasLimit:
        new_var_name = "IH_l"
        currentGasLimit = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = currentGasLimit

    new_var_name = "IH_s"
    currentTimestamp = BitVec(new_var_name, 256)
    path_conditions_and_vars[new_var_name] = currentTimestamp

    # the state of the current current contract
    if "Ia" not in global_state:
        global_state["Ia"] = {}
    global_state["miu_i"] = 0
    global_state["value"] = deposited_value
    global_state["sender_address"] = sender_address
    global_state["receiver_address"] = receiver_address
    global_state["gas_price"] = gas_price
    global_state["origin"] = origin
    global_state["currentCoinbase"] = currentCoinbase
    global_state["currentTimestamp"] = currentTimestamp
    global_state["currentNumber"] = currentNumber
    global_state["currentDifficulty"] = currentDifficulty
    global_state["currentGasLimit"] = currentGasLimit

    return global_state


def full_sym_exec():
    # executing, starting from beginning
    path_conditions_and_vars = {"path_condition" : []}
    global_state = get_init_global_state(path_conditions_and_vars)
    analysis = init_analysis()
    params = Parameter(path_conditions_and_vars=path_conditions_and_vars, global_state=global_state, analysis=analysis)
    execution_paths[total_no_of_paths] = []
    return sym_exec_block(params)


# Symbolically executing a block from the start address
def sym_exec_block(params):
    global solver
    #global visited_edges
    global path_conditions
    global all_gs
    global results
    global source_map
    global terminals
    global loop_limits

    block = params.block
    pre_block = params.pre_block
    visited = params.visited
    visited_edges = params.visited_edges
    depth = params.depth
    stack = params.stack
    mem = params.mem
    memory = params.memory
    global_state = params.global_state
    sha3_list = params.sha3_list
    path_conditions_and_vars = params.path_conditions_and_vars
    analysis = params.analysis
    models = params.models
    calls = params.calls
    func_call = params.func_call

    Edge = namedtuple("Edge", ["v1", "v2"]) # Factory Function for tuples is used as dictionary key
    if block < 0:
        log.debug("UNKNOWN JUMP ADDRESS. TERMINATING THIS PATH")
        return ["ERROR"]

    if global_params.DEBUG_MODE:
        print("Reach block address " + hex(block))
        #print("STACK: " + str(stack))

    current_edge = Edge(pre_block, block)
    if visited_edges.has_key(current_edge):
        updated_count_number = visited_edges[current_edge] + 1
        visited_edges.update({current_edge: updated_count_number})
    else:
        visited_edges.update({current_edge: 1})

    if visited_edges[current_edge] > global_params.LOOP_LIMIT:
        if jump_type[pre_block] == "conditional" and vertices[pre_block].get_falls_to() == block:
            if global_params.DEBUG_MODE:
                print("!!! Overcome a number of loop limit. Terminating this path ... !!!")
            return stack

    current_gas_used = analysis["gas"]
    if current_gas_used > global_params.GAS_LIMIT:
        if global_params.DEBUG_MODE:
            print("!!! Run out of gas. Terminating this path ... !!!")
        return stack

    # Execute every instruction, one at a time
    try:
        block_ins = vertices[block].get_instructions()
    except KeyError:
        if global_params.DEBUG_MODE:
            print("This path results in an exception, possibly an invalid jump address")
        return ["ERROR"]

    for instr in block_ins:
        if global_params.DEBUG_MODE:
            print(hex(global_state["pc"])+" \t "+str(instr))
        params.instr = instr
        sym_exec_ins(params)
    if global_params.DEBUG_MODE:
        print("")

    try:
        # Search for structs inside basic block
        sequence_of_instructions = ""
        for index in instructions:
            if index >= vertices[block].get_start_address() and index <= vertices[block].get_end_address():
                sequence_of_instructions += str(index)+" "+instructions[index]
        matches = re.compile("[0-9]+ DUP2 [0-9]+ PUSH1 0x([0-9]+) [0-9]+ ADD .+? [0-9]+ SWAP1 ([0-9]+) SSTORE").findall(sequence_of_instructions)
        if matches:
            # Check that that struct has more than one element and that the first element is stored to address 0
            if len(matches) > 1 and int(matches[0][0]) == 0:
                for match in matches:
                    struct = {}
                    struct["path_condition"]     = path_conditions_and_vars["path_condition"]
                    struct["function_signature"] = get_function_signature_from_path_condition(struct["path_condition"])
                    struct["address"]            = int(match[0])
                    struct["block"]              = params.block
                    struct["pc"]                 = int(match[1])
                    if not struct in list_of_structs:
                        list_of_structs.append(struct)
        else:
            matches = re.compile("[0-9]+ DUP2 ([0-9]+) SSTORE .+? [0-9]+ PUSH1 0x[0-9]+ [0-9]+ DUP[0-9] [0-9]+ ADD [0-9]+ SSTORE").findall(sequence_of_instructions)
            if matches:
                for sstore in list_of_sstores:
                    if sstore["pc"] == int(matches[0]) and sstore["address"] == 0:
                        struct = {}
                        struct["path_condition"]     = path_conditions_and_vars["path_condition"]
                        struct["function_signature"] = sstore["function_signature"]
                        struct["address"]            = sstore["address"]
                        struct["block"]              = params.block
                        struct["pc"]                 = sstore["pc"]
                        if not struct in list_of_structs:
                            list_of_structs.append(struct)
    except:
        pass

    # Mark that this basic block in the visited blocks
    visited.append(block)
    depth += 1

    # Go to next Basic Block(s)
    if jump_type[block] == "terminal" or depth > global_params.DEPTH_LIMIT:
        global total_no_of_paths

        total_no_of_paths += 1

        terminal = {}
        terminal["opcode"] = block_ins = vertices[block].get_instructions()[-1].replace(" ", "")
        terminal["path_condition"] = path_conditions_and_vars["path_condition"]
        terminals.append(terminal)

        if global_params.DEBUG_MODE:
            if depth > global_params.DEPTH_LIMIT:
                print "!!! DEPTH LIMIT EXCEEDED !!!"

        if global_params.DEBUG_MODE:
            print "Termintating path: "+str(total_no_of_paths)
            print "Depth: "+str(depth)
            print ""

        display_analysis(analysis)

    elif jump_type[block] == "unconditional":  # executing "JUMP"
        successor = vertices[block].get_jump_target()
        new_params = params.copy()
        new_params.depth = depth
        new_params.block = successor
        new_params.pre_block = block
        new_params.visited_edges = visited_edges
        new_params.global_state["pc"] = successor
        if source_map:
            source_code = source_map.find_source_code(global_state["pc"])
            if source_code in source_map.func_call_names:
                new_params.func_call = global_state["pc"]
        sym_exec_block(new_params)
    elif jump_type[block] == "falls_to":  # just follow to the next basic block
        successor = vertices[block].get_falls_to()
        new_params = params.copy()
        new_params.depth = depth
        new_params.block = successor
        new_params.pre_block = block
        new_params.visited_edges = visited_edges
        new_params.global_state["pc"] = successor
        sym_exec_block(new_params)
    elif jump_type[block] == "conditional":  # executing "JUMPI"
        # A choice point, we proceed with depth first search

        updated_count_number = visited_edges[current_edge] - 1
        visited_edges.update({current_edge: updated_count_number})

        current_execution_path = copy.deepcopy(execution_paths[total_no_of_paths])

        branch_expression = vertices[block].get_branch_expression()
        negated_branch_expression = Not(branch_expression)

        solver.reset()
        solver.add(path_conditions_and_vars["path_condition"])

        if global_params.DEBUG_MODE:
            print("Negated branch expression: " + remove_line_break_space(negated_branch_expression))

        if not negated_branch_expression in list_of_comparisons:
            list_of_comparisons[negated_branch_expression] = get_function_signature_from_path_condition(path_conditions_and_vars["path_condition"])

        solver.add(negated_branch_expression)

        isRightBranchFeasible = True

        try:
            try:
                if solver.check() == unsat and not (negated_branch_expression == True or negated_branch_expression == False or negated_branch_expression == Not(True) or negated_branch_expression == Not(False)):
                    isRightBranchFeasible = False
            except:
                isRightBranchFeasible = False
            if not isRightBranchFeasible:
                if not vertices[block].get_falls_to() in feasible_blocks:
                    infeasible_blocks.append(vertices[block].get_falls_to())
                if global_params.DEBUG_MODE:
                    print("RIGHT BRANCH IS INFEASIBLE ("+str(solver.check())+")")
            else:
                if vertices[block].get_falls_to() in infeasible_blocks:
                    infeasible_blocks.remove(vertices[block].get_falls_to())
                    for heuristic in heuristics:
                        if heuristic["block"] == vertices[block].get_falls_to():
                            heuristics.remove(heuristic)
                feasible_blocks.append(vertices[block].get_falls_to())
            right_branch = vertices[block].get_falls_to()
            new_params = params.copy()
            new_params.depth = depth
            new_params.block = right_branch
            new_params.pre_block = block
            new_params.visited_edges = visited_edges
            new_params.global_state["pc"] = right_branch
            new_params.is_feasible = isRightBranchFeasible
            new_params.path_conditions_and_vars["path_condition"].append(negated_branch_expression)
            sym_exec_block(new_params)
        except Exception as e:
            log_file.write(str(e))
            if global_params.DEBUG_MODE:
                traceback.print_exc()
            if str(e) == "timeout":
                raise e

        execution_paths[total_no_of_paths] = current_execution_path

        solver.reset()
        solver.add(path_conditions_and_vars["path_condition"])

        if global_params.DEBUG_MODE:
            print("Branch expression: " + remove_line_break_space(branch_expression))

        if not branch_expression in list_of_comparisons:
            list_of_comparisons[branch_expression] = get_function_signature_from_path_condition(path_conditions_and_vars["path_condition"])

        solver.add(branch_expression)

        isLeftBranchFeasible = True

        try:
            try:
                if solver.check() == unsat and not (branch_expression == True or branch_expression == False or branch_expression == Not(True) or branch_expression == Not(False)):
                    isLeftBranchFeasible = False
            except:
                isLeftBranchFeasible = False
            if not isLeftBranchFeasible:
                if not vertices[block].get_jump_target() in feasible_blocks:
                    infeasible_blocks.append(vertices[block].get_jump_target())
                if global_params.DEBUG_MODE:
                    print("LEFT BRANCH IS INFEASIBLE ("+str(solver.check())+")")
            else:
                if vertices[block].get_jump_target() in infeasible_blocks:
                    infeasible_blocks.remove(vertices[block].get_jump_target())
                    for heuristic in heuristics:
                        if heuristic["block"] == vertices[block].get_jump_target():
                            heuristics.remove(heuristic)
                feasible_blocks.append(vertices[block].get_jump_target())
            left_branch = vertices[block].get_jump_target()
            new_params = params.copy()
            new_params.depth = depth
            new_params.block = left_branch
            new_params.pre_block = block
            new_params.visited_edges = visited_edges
            new_params.global_state["pc"] = left_branch
            new_params.is_feasible = isLeftBranchFeasible
            new_params.path_conditions_and_vars["path_condition"].append(branch_expression)
            sym_exec_block(new_params)
        except Exception as e:
            log_file.write(str(e))
            if global_params.DEBUG_MODE:
                traceback.print_exc()
            if str(e) == "timeout":
                raise e
    else:
        updated_count_number = visited_edges[current_edge] - 1
        visited_edges.update({current_edge: updated_count_number})
        raise Exception('Unknown Jump-Type')

# Symbolically executing an instruction
def sym_exec_ins(params):
    global visited_pcs
    global solver
    global vertices
    global edges
    global source_map
    global g_timeout
    global execution_paths
    global account_balance

    if g_timeout:
        raise Exception("timeout")

    start = params.block
    instr = params.instr
    stack = params.stack
    mem = params.mem
    memory = params.memory
    global_state = params.global_state
    sha3_list = params.sha3_list
    path_conditions_and_vars = params.path_conditions_and_vars
    analysis = params.analysis
    models = params.models
    calls = params.calls
    func_call = params.func_call

    visited_pcs.add(global_state["pc"])

    instr_parts = str.split(instr, ' ')

    execution_paths[total_no_of_paths].append(global_state["pc"])

    # collecting the analysis result by calling this skeletal function
    # this should be done before symbolically executing the instruction,
    # since SE will modify the stack and mem
    update_analysis(analysis, instr_parts[0], stack, mem, global_state, path_conditions_and_vars, solver)

    log.debug("==============================")
    log.debug("EXECUTING: " + instr)

    #
    #  0s: Stop and Arithmetic Operations
    #
    if instr_parts[0] == "STOP":
        global_state["pc"] = global_state["pc"] + 1
        #return
    elif instr_parts[0] == "ADD":
        if len(stack) > 1:
            first = stack.pop(0)
            second = stack.pop(0)
            # Type conversion is needed when they are mismatched
            if isReal(first) and isSymbolic(second):
                first = BitVecVal(first, 256)
                computed = first + second
            elif isSymbolic(first) and isReal(second):
                second = BitVecVal(second, 256)
                computed = first + second
            else:
                # both are real and we need to manually modulus with 2 ** 256
                # if both are symbolic z3 takes care of modulus automatically
                computed = (first + second) % (2 ** 256)
            computed = simplify(computed) if is_expr(computed) else computed
            if isReal(computed):
                if not global_state["pc"] in list_of_additions:
                    list_of_additions[global_state["pc"]] = []
                if not computed in list_of_additions[global_state["pc"]]:
                    list_of_additions[global_state["pc"]].append(computed)
            stack.insert(0, computed)
            global_state["pc"] = global_state["pc"] + 1
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "MUL":
        if len(stack) > 1:
            first = stack.pop(0)
            second = stack.pop(0)
            if isReal(first) and isSymbolic(second):
                first = BitVecVal(first, 256)
            elif isSymbolic(first) and isReal(second):
                second = BitVecVal(second, 256)
            computed = first * second & UNSIGNED_BOUND_NUMBER
            computed = simplify(computed) if is_expr(computed) else computed
            if isReal(computed):
                if not global_state["pc"] in list_of_multiplications:
                    list_of_multiplications[global_state["pc"]] = []
                if not computed in list_of_multiplications[global_state["pc"]]:
                    list_of_multiplications[global_state["pc"]].append(computed)
            stack.insert(0, computed)
            global_state["pc"] = global_state["pc"] + 1
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "SUB":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isReal(first) and isSymbolic(second):
                first = BitVecVal(first, 256)
                computed = first - second
            elif isSymbolic(first) and isReal(second):
                second = BitVecVal(second, 256)
                computed = first - second
            else:
                computed = (first - second) % (2 ** 256)
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "DIV":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if second == 0:
                    computed = 0
                else:
                    first = to_unsigned(first)
                    second = to_unsigned(second)
                    computed = first / second
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add(Not(second == 0))
                if check_solver(solver) == unsat:
                    computed = 0
                else:
                    computed = UDiv(first, second)
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "SDIV":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                first = to_signed(first)
                second = to_signed(second)
                if second == 0:
                    computed = 0
                elif first == -2**255 and second == -1:
                    computed = -2**255
                else:
                    sign = -1 if (first / second) < 0 else 1
                    computed = sign * ( abs(first) / abs(second) )
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add(Not(second == 0))
                if check_solver(solver) == unsat:
                    computed = 0
                else:
                    solver.push()
                    solver.add( Not( And(first == -2**255, second == -1 ) ))
                    if check_solver(solver) == unsat:
                        computed = -2**255
                    else:
                        s = Solver()
                        s.set("timeout", global_params.TIMEOUT)
                        s.add(first / second < 0)
                        sign = -1 if check_solver(s) == sat else 1
                        z3_abs = lambda x: If(x >= 0, x, -x)
                        first = z3_abs(first)
                        second = z3_abs(second)
                        computed = sign * (first / second)
                    solver.pop()
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "MOD":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if second == 0:
                    computed = 0
                else:
                    first = to_unsigned(first)
                    second = to_unsigned(second)
                    computed = first % second & UNSIGNED_BOUND_NUMBER
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add(Not(second == 0))
                if check_solver(solver) == unsat:
                    # it is provable that second is indeed equal to zero
                    computed = 0
                else:
                    computed = URem(first, second)
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "SMOD":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if second == 0:
                    computed = 0
                else:
                    first = to_signed(first)
                    second = to_signed(second)
                    sign = -1 if first < 0 else 1
                    computed = sign * (abs(first) % abs(second))
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add(Not(second == 0))
                if check_solver(solver) == unsat:
                    # it is provable that second is indeed equal to zero
                    computed = 0
                else:
                    solver.push()
                    solver.add(first < 0) # check sign of first element
                    sign = BitVecVal(-1, 256) if check_solver(solver) == sat \
                        else BitVecVal(1, 256)
                    solver.pop()
                    z3_abs = lambda x: If(x >= 0, x, -x)
                    first = z3_abs(first)
                    second = z3_abs(second)
                    computed = sign * (first % second)
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "ADDMOD":
        if len(stack) > 2:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            third = stack.pop(0)
            if isAllReal(first, second, third):
                if third == 0:
                    computed = 0
                else:
                    computed = (first + second) % third
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                third = to_symbolic(third)
                solver.push()
                solver.add(Not(third == 0))
                if check_solver(solver) == unsat:
                    computed = 0
                else:
                    first = ZeroExt(256, first)
                    second = ZeroExt(256, second)
                    third = ZeroExt(256, third)
                    computed = (first + second) % third
                    computed = Extract(255, 0, computed)
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "MULMOD":
        if len(stack) > 2:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            third = stack.pop(0)
            if isAllReal(first, second, third):
                if third == 0:
                    computed = 0
                else:
                    computed = (first * second) % third
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                third = to_symbolic(third)
                solver.push()
                solver.add(Not(third == 0))
                if check_solver(solver) == unsat:
                    computed = 0
                else:
                    first = ZeroExt(256, first)
                    second = ZeroExt(256, second)
                    third = ZeroExt(256, third)
                    computed = URem(first * second, third)
                    computed = Extract(255, 0, computed)
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            instruction_object.data_out = [computed]
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "EXP":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            base = stack.pop(0)
            exponent = stack.pop(0)
            # Type conversion is needed when they are mismatched
            if isAllReal(base, exponent):
                computed = pow(base, exponent, 2**256)
            else:
                # The computed value is unknown, this is because power is
                # not supported in bit-vector theory
                new_var_name = gen.gen_arbitrary_var()
                computed = BitVec(new_var_name, 256)
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "SIGNEXTEND":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if first >= 32 or first < 0:
                    computed = second
                else:
                    signbit_index_from_right = 8 * first + 7
                    if second & (1 << signbit_index_from_right):
                        computed = second | (2 ** 256 - (1 << signbit_index_from_right))
                    else:
                        computed = second & ((1 << signbit_index_from_right) - 1 )
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add(Not(Or(first >= 32, first < 0)))
                if check_solver(solver) == unsat:
                    computed = second
                else:
                    signbit_index_from_right = 8 * first + 7
                    solver.push()
                    solver.add(second & (1 << signbit_index_from_right) == 0)
                    if check_solver(solver) == unsat:
                        computed = second | (2 ** 256 - (1 << signbit_index_from_right))
                    else:
                        computed = second & ((1 << signbit_index_from_right) - 1)
                    solver.pop()
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            instruction_object.data_out = [computed]
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    #
    #  10s: Comparison and Bitwise Logic Operations
    #
    elif instr_parts[0] == "LT":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                first = to_unsigned(first)
                second = to_unsigned(second)
                if first < second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(ULT(first, second), BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "GT":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                first = to_unsigned(first)
                second = to_unsigned(second)
                if first > second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(UGT(first, second), BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "SLT":  # Not fully faithful to signed comparison
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                first = to_signed(first)
                second = to_signed(second)
                if first < second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(first < second, BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "SGT":  # Not fully faithful to signed comparison
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                first = to_signed(first)
                second = to_signed(second)
                if first > second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(first > second, BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "EQ":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            if isAllReal(first, second):
                if first == second:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(first == second, BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "ISZERO":
        # Tricky: this instruction works on both boolean and integer,
        # when we have a symbolic expression, type error might occur
        # Currently handled by try and catch
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            flag = stack.pop(0)
            if isReal(flag):
                if flag == 0:
                    computed = 1
                else:
                    computed = 0
            else:
                computed = If(flag == 0, BitVecVal(1, 256), BitVecVal(0, 256))
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "AND":
        if len(stack) > 1:
            first = stack.pop(0)
            second = stack.pop(0)
            computed = first & second
            computed = simplify(computed) if is_expr(computed) else computed
            if (isReal(first) and hex(first) == "0xff") or (isReal(second) and hex(second) == "0xff"):
                if not global_state["pc"] in list_of_vars:
                     list_of_vars[global_state["pc"]] = []
                if isReal(first) and hex(first) == "0xff":
                    list_of_vars[global_state["pc"]].append(second)
                if isReal(second) and hex(second) == "0xff":
                    list_of_vars[global_state["pc"]].append(first)
            stack.insert(0, computed)
            global_state["pc"] = global_state["pc"] + 1
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "OR":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            computed = first | second
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "XOR":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            second = stack.pop(0)
            computed = first ^ second
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "NOT":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            computed = (~first) & UNSIGNED_BOUND_NUMBER
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "BYTE":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            first = stack.pop(0)
            byte_index = 32 - first - 1
            second = stack.pop(0)

            if isAllReal(first, second):
                if first >= 32 or first < 0:
                    computed = 0
                else:
                    computed = second & (255 << (8 * byte_index))
                    computed = computed >> (8 * byte_index)
            else:
                first = to_symbolic(first)
                second = to_symbolic(second)
                solver.push()
                solver.add( Not (Or( first >= 32, first < 0 ) ) )
                if check_solver(solver) == unsat:
                    computed = 0
                else:
                    computed = second & (255 << (8 * byte_index))
                    computed = computed >> (8 * byte_index)
                solver.pop()
            computed = simplify(computed) if is_expr(computed) else computed
            stack.insert(0, computed)
        else:
            raise ValueError('STACK underflow')
    #
    # 20s: SHA3
    #
    elif instr_parts[0] == "SHA3":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            s0 = stack.pop(0)
            s1 = stack.pop(0)
            if isAllReal(s0, s1):
                data = [mem[s0+i*32] for i in range(s1/32)]
                input = ''
                symbolic = False
                for value in data:
                    if is_expr(value):
                        input += str(value)
                        symbolic = True
                    else:
                        input += binascii.unhexlify('%064x' % value)
                if input in sha3_list:
                    stack.insert(0, sha3_list[input])
                else:
                    if symbolic:
                        new_var_name = ""
                        for i in reversed(range(s1/32)):
                            if is_expr(mem[s0+i*32]):
                                new_var_name += str(get_vars(mem[s0+i*32])[0])
                            else:
                                new_var_name += str(mem[s0+i*32])
                            if i != 0:
                                new_var_name += "_"
                        new_var = BitVec(new_var_name, 256)
                        sha3_list[input] = new_var
                        path_conditions_and_vars[new_var_name] = new_var
                        stack.insert(0, new_var)
                    else:
                        hash = sha3.keccak_256(input).hexdigest()
                        new_var = int(hash, 16)
                        sha3_list[input] = new_var
                        stack.insert(0, new_var)
            else:
                new_var_name = gen.gen_arbitrary_var()
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var
                stack.insert(0, new_var)
        else:
            raise ValueError('STACK underflow')
    #
    # 30s: Environment Information
    #
    elif instr_parts[0] == "ADDRESS":  # get address of currently executing account
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, path_conditions_and_vars["Ia"])
    elif instr_parts[0] == "BALANCE":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            address = stack.pop(0)
            if isReal(address) and global_params.USE_GLOBAL_BLOCKCHAIN:
                balance = data_source.getBalance(address)
            else:
                new_var_name = gen.gen_balance_var(address)
                if path_conditions_and_vars["Ia"] in get_vars(address):
                    new_var_name = gen.gen_balance_var(path_conditions_and_vars["Ia"])
                    account_balance = new_var_name
                if new_var_name in path_conditions_and_vars:
                    balance = path_conditions_and_vars[new_var_name]
                else:
                    balance = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = balance
                    if path_conditions_and_vars["Ia"] in get_vars(address):
                        path_conditions_and_vars["path_condition"].append(balance > 0)
                        path_conditions_and_vars["path_condition"].append(balance == balance + path_conditions_and_vars["Iv"])
            if isReal(address):
                hashed_address = "concrete_address_" + str(address)
            else:
                hashed_address = str(address)
            global_state["balance"][hashed_address] = balance
            stack.insert(0, balance)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "CALLER":  # get caller address
        # that is directly responsible for this execution
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["sender_address"])
    elif instr_parts[0] == "ORIGIN":  # get execution origination address
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["origin"])
    elif instr_parts[0] == "CALLVALUE":  # get value of this transaction
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["value"])
    elif instr_parts[0] == "CALLDATALOAD":  # from input data from environment
        if len(stack) > 0:
            position = stack.pop(0)
            if isReal(position) and position != 0:
                function_signature = None
                for condition in path_conditions_and_vars["path_condition"]:
                    if is_expr(condition) and str(condition).startswith("If(Extract(255, 224, Id_1) == "):
                        match = re.compile("Extract\(255, 224, Id_1\) == ([0-9]+)").findall(str(condition))
                        if match:
                            function_signature = int(match[0])
                if not function_signature in list_of_functions:
                    list_of_functions[function_signature] = []
                calldataload = {}
                calldataload["block"] = params.block
                calldataload["pc"] = global_state["pc"]
                calldataload["position"] = position
                list_of_functions[function_signature].append(calldataload)
            #if source_map:
            #    source_code = source_map.find_source_code(global_state["pc"] - 1)
            #    if source_code.startswith("function") and isReal(position):
            #        idx1 = source_code.index("(") + 1
            #        idx2 = source_code.index(")")
            #        params_code = source_code[idx1:idx2]
            #        params_list = params_code.split(",")
            #        params_list = [param.split(" ")[-1] for param in params_list]
            #        param_idx = (position - 4) / 32
            #        new_var_name = params_list[param_idx]
            #        source_map.var_names.append(new_var_name)
            #    else:
            #    new_var_name = gen.gen_data_var(position)
            #else:
            new_var_name = gen.gen_data_var(position)
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var
            stack.insert(0, new_var)
            global_state["pc"] = global_state["pc"] + 1
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "CALLDATASIZE":
        global_state["pc"] = global_state["pc"] + 1
        new_var_name = gen.gen_data_size()
        if new_var_name in path_conditions_and_vars:
            new_var = path_conditions_and_vars[new_var_name]
        else:
            new_var = BitVec(new_var_name, 256)
            path_conditions_and_vars[new_var_name] = new_var
        stack.insert(0, new_var)
    elif instr_parts[0] == "CALLDATACOPY":  # Copy input data to memory
        #  TODO: Don't know how to simulate this yet
        if len(stack) > 2:
            global_state["pc"] = global_state["pc"] + 1
            stack.pop(0)
            stack.pop(0)
            stack.pop(0)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "CODESIZE":
        if c_name.endswith('.disasm'):
            evm_file_name = c_name[:-7]
        else:
            evm_file_name = c_name
        with open(evm_file_name, 'r') as evm_file:
            evm = evm_file.read()[:-1]
            code_size = len(evm)/2
            stack.insert(0, code_size)
    elif instr_parts[0] == "CODECOPY":
        if len(stack) > 2:
            global_state["pc"] = global_state["pc"] + 1
            mem_location = stack.pop(0)
            code_from = stack.pop(0)
            no_bytes = stack.pop(0)
            current_miu_i = global_state["miu_i"]

            if isAllReal(mem_location, current_miu_i, code_from, no_bytes):
                temp = long(math.ceil((mem_location + no_bytes) / float(32)))
                if temp > current_miu_i:
                    current_miu_i = temp

                if c_name.endswith('.disasm'):
                    evm_file_name = c_name[:-7]
                else:
                    evm_file_name = c_name
                with open(evm_file_name, 'r') as evm_file:
                    evm = evm_file.read()[:-1]
                    start = code_from * 2
                    end = start + no_bytes * 2
                    code = evm[start: end]
                mem[mem_location] = int(code, 16)
            else:
                new_var_name = gen.gen_code_var("Ia", code_from, no_bytes)
                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var

                temp = ((mem_location + no_bytes) / 32) + 1
                current_miu_i = to_symbolic(current_miu_i)
                expression = current_miu_i < temp
                solver.push()
                solver.add(expression)
                if check_solver(solver) != unsat:
                    current_miu_i = If(expression, temp, current_miu_i)
                solver.pop()
                mem.clear() # very conservative
                mem[str(mem_location)] = new_var
            global_state["miu_i"] = current_miu_i
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "GASPRICE":
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["gas_price"])
    elif instr_parts[0] == "EXTCODESIZE":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            address = stack.pop(0)
            if isReal(address) and global_params.USE_GLOBAL_BLOCKCHAIN:
                code = data_source.getCode(address)
                stack.insert(0, len(code)/2)
            else:
                #not handled yet
                new_var_name = gen.gen_code_size_var(address)
                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var
                stack.insert(0, new_var)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "EXTCODECOPY":
        if len(stack) > 3:
            global_state["pc"] = global_state["pc"] + 1
            address = stack.pop(0)
            mem_location = stack.pop(0)
            code_from = stack.pop(0)
            no_bytes = stack.pop(0)
            current_miu_i = global_state["miu_i"]

            if isAllReal(address, mem_location, current_miu_i, code_from, no_bytes) and USE_GLOBAL_BLOCKCHAIN:
                temp = long(math.ceil((mem_location + no_bytes) / float(32)))
                if temp > current_miu_i:
                    current_miu_i = temp

                evm = data_source.getCode(address)
                start = code_from * 2
                end = start + no_bytes * 2
                code = evm[start: end]
                mem[mem_location] = int(code, 16)
            else:
                new_var_name = gen.gen_code_var(address, code_from, no_bytes)
                if new_var_name in path_conditions_and_vars:
                    new_var = path_conditions_and_vars[new_var_name]
                else:
                    new_var = BitVec(new_var_name, 256)
                    path_conditions_and_vars[new_var_name] = new_var

                temp = ((mem_location + no_bytes) / 32) + 1
                current_miu_i = to_symbolic(current_miu_i)
                expression = current_miu_i < temp
                solver.push()
                solver.add(expression)
                if check_solver(solver) != unsat:
                    current_miu_i = If(expression, temp, current_miu_i)
                solver.pop()
                mem.clear() # very conservative
                mem[str(mem_location)] = new_var
            global_state["miu_i"] = current_miu_i
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "RETURNDATACOPY":
        if len(stack) > 2:
            global_state["pc"] += 1
            stack.pop(0)
            stack.pop(0)
            stack.pop(0)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "RETURNDATASIZE":
        global_state["pc"] += 1
        new_var_name = gen.gen_arbitrary_var()
        new_var = BitVec(new_var_name, 256)
        stack.insert(0, new_var)
    #
    #  40s: Block Information
    #
    elif instr_parts[0] == "BLOCKHASH":  # information from block header
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            stack.pop(0)
            new_var_name = "IH_blockhash"
            if new_var_name in path_conditions_and_vars:
                new_var = path_conditions_and_vars[new_var_name]
            else:
                new_var = BitVec(new_var_name, 256)
                path_conditions_and_vars[new_var_name] = new_var
            stack.insert(0, new_var)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "COINBASE":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentCoinbase"])
    elif instr_parts[0] == "TIMESTAMP":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentTimestamp"])
    elif instr_parts[0] == "NUMBER":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentNumber"])
    elif instr_parts[0] == "DIFFICULTY":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentDifficulty"])
    elif instr_parts[0] == "GASLIMIT":  # information from block header
        global_state["pc"] = global_state["pc"] + 1
        stack.insert(0, global_state["currentGasLimit"])
    #
    #  50s: Stack, Memory, Storage, and Flow Information
    #
    elif instr_parts[0] == "POP":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            stack.pop(0)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "MLOAD":
        if len(stack) > 0:
            global_state["pc"] = global_state["pc"] + 1
            address = stack.pop(0)
            current_miu_i = global_state["miu_i"]
            if isAllReal(address, current_miu_i) and address in mem:
                temp = long(math.ceil((address + 32) / float(32)))
                if temp > current_miu_i:
                    current_miu_i = temp
                value = mem[address]
                stack.insert(0, value)
                log.debug("temp: " + str(temp))
                log.debug("current_miu_i: " + str(current_miu_i))
            else:
                temp = ((address + 31) / 32) + 1
                current_miu_i = to_symbolic(current_miu_i)
                expression = current_miu_i < temp
                #solver.push()
                #solver.add(expression)
                #if check_solver(solver) != unsat:
                    # this means that it is possibly that current_miu_i < temp
                #    current_miu_i = If(expression,temp,current_miu_i)
                #solver.pop()
                if address in mem:
                    value = mem[address]
                    stack.insert(0, value)
                else:
                    new_var_name = gen.gen_mem_var(address)
                    if not new_var_name in path_conditions_and_vars:
                        path_conditions_and_vars[new_var_name] = BitVec(new_var_name, 256)
                    new_var = path_conditions_and_vars[new_var_name]
                    stack.insert(0, new_var)
                    mem[address] = new_var
                log.debug("temp: " + str(temp))
                log.debug("current_miu_i: " + str(current_miu_i))
            global_state["miu_i"] = current_miu_i
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "MSTORE":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            stored_address = stack.pop(0)
            stored_value = stack.pop(0)
            current_miu_i = global_state["miu_i"]
            if isReal(stored_address):
                # preparing data for hashing later
                old_size = len(memory) // 32
                new_size = ceil32(stored_address + 32) // 32
                mem_extend = (new_size - old_size) * 32
                memory.extend([0] * mem_extend)
                value = stored_value
                for i in range(31, -1, -1):
                    memory[stored_address + i] = value % 256
                    value /= 256
            if isAllReal(stored_address, current_miu_i):
                temp = long(math.ceil((stored_address + 32) / float(32)))
                if temp > current_miu_i:
                    current_miu_i = temp
                mem[stored_address] = stored_value  # note that the stored_value could be symbolic
                log.debug("temp: " + str(temp))
                log.debug("current_miu_i: " + str(current_miu_i))
            else:
                log.debug("temp: " + str(stored_address))
                temp = ((stored_address + 31) / 32) + 1
                log.debug("current_miu_i: " + str(current_miu_i))
                expression = current_miu_i < temp
                log.debug("Expression: " + str(expression))
                #solver.push()
                #solver.add(expression)
                #if check_solver(solver) != unsat:
                    # this means that it is possibly that current_miu_i < temp
                #    current_miu_i = If(expression,temp,current_miu_i)
                #solver.pop()
                #mem.clear()  # very conservative
                mem[stored_address] = stored_value
                log.debug("temp: " + str(temp))
                log.debug("current_miu_i: " + str(current_miu_i))
            global_state["miu_i"] = current_miu_i
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "MSTORE8":
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            stored_address = stack.pop(0)
            temp_value = stack.pop(0)
            stored_value = temp_value % 256  # get the least byte
            current_miu_i = global_state["miu_i"]
            if isAllReal(stored_address, current_miu_i):
                temp = long(math.ceil((stored_address + 1) / float(32)))
                if temp > current_miu_i:
                    current_miu_i = temp
                mem[stored_address] = stored_value  # note that the stored_value could be symbolic
            else:
                temp = (stored_address / 32) + 1
                if isReal(current_miu_i):
                    current_miu_i = BitVecVal(current_miu_i, 256)
                expression = current_miu_i < temp
                solver.push()
                solver.add(expression)
                if check_solver(solver) != unsat:
                    # this means that it is possibly that current_miu_i < temp
                    current_miu_i = If(expression,temp,current_miu_i)
                solver.pop()
                mem[stored_address] = stored_value
                #mem.clear()  # very conservative
            global_state["miu_i"] = current_miu_i
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "SLOAD":
        if len(stack) > 0:
            address = stack.pop(0)
            if is_expr(address):
                address = simplify(address)
            if address in global_state["Ia"]:
                value = global_state["Ia"][address]
                stack.insert(0, value)
            else:
                new_var_name = gen.gen_owner_store_var(address)
                if not new_var_name in path_conditions_and_vars:
                    if address.__class__.__name__ == "BitVecNumRef":
                        address = address.as_long()
                    else:
                        path_conditions_and_vars[new_var_name] = BitVec(new_var_name, 256)
                new_var = path_conditions_and_vars[new_var_name]
                stack.insert(0, new_var)
                global_state["Ia"][address] = new_var
            global_state["pc"] = global_state["pc"] + 1
        else:
            raise ValueError('STACK underflow')

    elif instr_parts[0] == "SSTORE":
        if len(stack) > 1:
            stored_address = stack.pop(0)
            stored_value = stack.pop(0)
            sstore = {}
            sstore["block"]              = params.block
            sstore["pc"]                 = global_state["pc"]
            sstore["address"]            = stored_address
            sstore["value"]              = stored_value
            if stored_address in global_state["Ia"]:
                sstore["variable"]       = global_state["Ia"][stored_address]
            else:
                sstore["variable"]       = BitVec(gen.gen_owner_store_var(stored_address), 256)
            sstore["path_condition"]     = path_conditions_and_vars["path_condition"]
            sstore["function_signature"] = get_function_signature_from_path_condition(sstore["path_condition"])
            if not sstore in list_of_sstores:
                list_of_sstores.append(sstore)
            global_state["pc"] = global_state["pc"] + 1
            global_state["Ia"][stored_address] = stored_value
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "JUMP":
        if len(stack) > 0:
            target_address = stack.pop(0)
            if isSymbolic(target_address):
                try:
                    target_address = int(str(simplify(target_address)))
                except:
                    raise TypeError("Target address must be an integer: "+str(target_address))
            vertices[start].set_jump_target(target_address)
            if target_address not in edges[start]:
                edges[start].append(target_address)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "JUMPI":
        # We need to prepare two branches
        if len(stack) > 1:
            target_address = stack.pop(0)
            if isSymbolic(target_address):
                try:
                    target_address = int(str(simplify(target_address)))
                except:
                    raise TypeError("Target address must be an integer: "+str(target_address))
            vertices[start].set_jump_target(target_address)
            flag = stack.pop(0)

            if flag.__class__.__name__ == "BitVecNumRef":
                flag = flag.as_long()

            branch_expression = (flag != 0)

            function_signature = None
            if is_expr(branch_expression) and str(branch_expression).startswith("If(Extract(255, 224, Id_1) == "):
                match = re.compile("Extract\(255, 224, Id_1\) == ([0-9]+)").findall(str(branch_expression))
                if match:
                    function_signature = int(match[0])
            if function_signature and not function_signature in list_of_functions:
                list_of_functions[function_signature] = []

            vertices[start].set_branch_expression(branch_expression)
            if target_address not in edges[start]:
                edges[start].append(target_address)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "PC":
        stack.insert(0, global_state["pc"])
        global_state["pc"] = global_state["pc"] + 1
    elif instr_parts[0] == "MSIZE":
        global_state["pc"] = global_state["pc"] + 1
        msize = 32 * global_state["miu_i"]
        stack.insert(0, msize)
    elif instr_parts[0] == "GAS":
        # In general, we do not have this precisely. It depends on both
        # the initial gas and the amount has been depleted
        # we need to think about this in the future, in case precise gas
        # can be tracked
        global_state["pc"] = global_state["pc"] + 1
        new_var_name = gen.gen_gas_var()
        new_var = BitVec(new_var_name, 256)
        path_conditions_and_vars[new_var_name] = new_var
        stack.insert(0, new_var)
    elif instr_parts[0] == "JUMPDEST":
        # Literally do nothing
        global_state["pc"] = global_state["pc"] + 1
    #
    #  60s & 70s: Push Operations
    #
    elif instr_parts[0].startswith('PUSH', 0):  # this is a push instruction
        position = int(instr_parts[0][4:], 10)
        global_state["pc"] = global_state["pc"] + 1 + position
        pushed_value = int(instr_parts[1], 16)
        stack.insert(0, pushed_value)
    #
    #  80s: Duplication Operations
    #
    elif instr_parts[0].startswith("DUP", 0):
        global_state["pc"] = global_state["pc"] + 1
        position = int(instr_parts[0][3:], 10) - 1
        if len(stack) > position:
            duplicate = stack[position]
            stack.insert(0, duplicate)
        else:
            raise ValueError('STACK underflow')

    #
    #  90s: Swap Operations
    #
    elif instr_parts[0].startswith("SWAP", 0):
        global_state["pc"] = global_state["pc"] + 1
        position = int(instr_parts[0][4:], 10)
        if len(stack) > position:
            temp = stack[position]
            stack[position] = stack[0]
            stack[0] = temp
        else:
            raise ValueError('STACK underflow')

    #
    #  a0s: Logging Operations
    #
    elif instr_parts[0] in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
        global_state["pc"] = global_state["pc"] + 1
        # We do not simulate these log operations
        num_of_pops = 2 + int(instr_parts[0][3:])
        while num_of_pops > 0:
            stack.pop(0)
            num_of_pops -= 1

    #
    #  f0s: System Operations
    #
    elif instr_parts[0] == "CREATE":
        if len(stack) > 2:
            global_state["pc"] += 1
            stack.pop(0)
            stack.pop(0)
            stack.pop(0)
            new_var_name = gen.gen_arbitrary_var()
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "CALL":
        # TODO: Need to handle miu_i
        if len(stack) > 6:
            outgas = stack.pop(0)
            recipient = stack.pop(0)
            transfer_amount = stack.pop(0)
            start_data_input = stack.pop(0)
            size_data_input = stack.pop(0)
            start_data_output = stack.pop(0)
            size_data_ouput = stack.pop(0)
            call = {}
            call["path_condition"]     = copy.deepcopy(path_conditions_and_vars["path_condition"])
            call["function_signature"] = get_function_signature_from_path_condition(call["path_condition"])
            call["recipient"]          = recipient
            call["value"]              = transfer_amount
            call["input_offset"]       = start_data_input
            call["input_size"]         = size_data_input
            call["memory"]             = mem
            call["block"]              = params.block
            call["type"]               = "CALL"
            call["gas"]                = outgas
            call["pc"]                 = global_state["pc"]
            call["id"]                 = len(list_of_calls)
            if not total_no_of_paths in list_of_calls:
                list_of_calls[total_no_of_paths] = []
            if call not in list_of_calls[total_no_of_paths]:
                list_of_calls[total_no_of_paths].append(call)
            # in the paper, it is shaky when the size of data output is
            # min of stack[6] and the | o |
            if isReal(transfer_amount) and transfer_amount == 0:
                stack.insert(0, 1)   # x = 0
            else:
                # Let us ignore the call depth
                balance_ia = global_state["balance"]["Ia"]
                is_enough_fund = (transfer_amount <= balance_ia)
                solver.push()
                solver.add(is_enough_fund)
                if check_solver(solver) == unsat:
                    # this means not enough fund, thus the execution will result in exception
                    solver.pop()
                    stack.insert(0, 0)   # x = 0
                else:
                    # the execution is possibly okay
                    stack.insert(0, 1)   # x = 1
                    solver.pop()
                    solver.add(is_enough_fund)
                    path_conditions_and_vars["path_condition"].append(is_enough_fund)
                    last_idx = len(path_conditions_and_vars["path_condition"]) - 1
                    analysis["time_dependency_bug"][last_idx] = global_state["pc"] - 1
                    new_balance_ia = (balance_ia - transfer_amount)
                    global_state["balance"]["Ia"] = new_balance_ia
                    address_is = path_conditions_and_vars["Is"]
                    address_is = (address_is & CONSTANT_ONES_159)
                    boolean_expression = (recipient != address_is)
                    solver.push()
                    solver.add(boolean_expression)
                    if check_solver(solver) == unsat:
                        solver.pop()
                        new_balance_is = (global_state["balance"]["Is"] + transfer_amount)
                        global_state["balance"]["Is"] = new_balance_is
                    else:
                        solver.pop()
                        if isReal(recipient):
                            new_address_name = "concrete_address_" + str(recipient)
                        else:
                            new_address_name = gen.gen_arbitrary_address_var()
                        old_balance_name = gen.gen_arbitrary_var()
                        old_balance = BitVec(old_balance_name, 256)
                        path_conditions_and_vars[old_balance_name] = old_balance
                        constraint = (old_balance >= 0)
                        solver.add(constraint)
                        path_conditions_and_vars["path_condition"].append(constraint)
                        new_balance = (old_balance + transfer_amount)
                        global_state["balance"][new_address_name] = new_balance
            global_state["pc"] = global_state["pc"] + 1
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "CALLCODE":
        # TODO: Need to handle miu_i
        if len(stack) > 6:
            global_state["pc"] = global_state["pc"] + 1
            outgas = stack.pop(0)
            stack.pop(0) # this is not used as recipient
            transfer_amount = stack.pop(0)
            start_data_input = stack.pop(0)
            size_data_input = stack.pop(0)
            start_data_output = stack.pop(0)
            size_data_ouput = stack.pop(0)
            # in the paper, it is shaky when the size of data output is
            # min of stack[6] and the | o |

            if isReal(transfer_amount):
                if transfer_amount == 0:
                    stack.insert(0, 1)   # x = 0
                    return

            # Let us ignore the call depth
            balance_ia = global_state["balance"]["Ia"]
            is_enough_fund = (transfer_amount <= balance_ia)
            solver.push()
            solver.add(is_enough_fund)
            if check_solver(solver) == unsat:
                # this means not enough fund, thus the execution will result in exception
                solver.pop()
                stack.insert(0, 0)   # x = 0
            else:
                # the execution is possibly okay
                stack.insert(0, 1)   # x = 1
                solver.pop()
                solver.add(is_enough_fund)
                path_conditions_and_vars["path_condition"].append(is_enough_fund)
                last_idx = len(path_conditions_and_vars["path_condition"]) - 1
                analysis["time_dependency_bug"][last_idx]
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "DELEGATECALL" or instr_parts[0] == "STATICCALL":
        if len(stack) > 5:
            global_state["pc"] += 1
            outgas = stack.pop(0)
            recipient = stack.pop(0)
            start_data_input = stack.pop(0)
            size_data_input = stack.pop(0)
            start_data_output = stack.pop(0)
            size_data_ouput = stack.pop(0)
            call = {}
            call["path_condition"]     = path_conditions_and_vars["path_condition"]
            call["function_signature"] = get_function_signature_from_path_condition(call["path_condition"])
            call["recipient"]          = recipient
            call["value"]              = None
            call["input_offset"]       = start_data_input
            call["input_size"]         = size_data_input
            call["memory"]             = mem
            call["block"]              = params.block
            call["type"]               = instr_parts[0]
            call["gas"]                = outgas
            call["pc"]                 = global_state["pc"]
            call["id"]                 = len(list_of_calls)
            if not total_no_of_paths in list_of_calls:
                list_of_calls[total_no_of_paths] = []
            if not call in list_of_calls[total_no_of_paths]:
                list_of_calls[total_no_of_paths].append(call)
            new_var_name = gen.gen_arbitrary_var()
            new_var = BitVec(new_var_name, 256)
            stack.insert(0, new_var)
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "RETURN" or instr_parts[0] == "REVERT":
        # TODO: Need to handle miu_i
        if len(stack) > 1:
            global_state["pc"] = global_state["pc"] + 1
            stack.pop(0)
            stack.pop(0)
            pass
        else:
            raise ValueError('STACK underflow')
    elif instr_parts[0] == "SUICIDE" or instr_parts[0] == "SELFDESTRUCT":
        global suicidal
        suicidal = True
        recipient = stack.pop(0)
        transfer_amount = global_state["balance"]["Ia"]
        suicide = {}
        suicide["path_condition"]     = path_conditions_and_vars["path_condition"]
        suicide["function_signature"] = get_function_signature_from_path_condition(suicide["path_condition"])
        suicide["recipient"]          = recipient
        suicide["value"]              = transfer_amount
        suicide["block"]              = params.block
        suicide["pc"]                 = global_state["pc"]
        if suicide not in list_of_suicides:
            list_of_suicides.append(suicide)
        global_state["balance"]["Ia"] = 0
        if isReal(recipient):
            new_address_name = "concrete_address_" + str(recipient)
        else:
            new_address_name = gen.gen_arbitrary_address_var()
        old_balance_name = gen.gen_arbitrary_var()
        old_balance = BitVec(old_balance_name, 256)
        path_conditions_and_vars[old_balance_name] = old_balance
        constraint = (old_balance >= 0)
        solver.add(constraint)
        path_conditions_and_vars["path_condition"].append(constraint)
        new_balance = (old_balance + transfer_amount)
        global_state["balance"][new_address_name] = new_balance
        global_state["pc"] = global_state["pc"] + 1
    elif instr_parts[0] == "INVALID":
        pass
    elif instr_parts[0] == "ASSERTFAIL":
        pass
    else:
        print("UNKNOWN INSTRUCTION: " + instr_parts[0])
        raise Exception('UNKNOWN INSTRUCTION: ' + instr_parts[0])

    try:
        print_state(stack, mem, global_state)
    except:
        log.debug("Error: Debugging states")

########################################################
#                      Heuristics                      #
########################################################

########################################################
#                    H0: Cash Flow                    #
########################################################
def detect_cash_flow():
    # Check if money could potentially go in
    money_flow_in = False
    for terminal in terminals:
        if terminal["opcode"] != "REVERT":
            s = Solver()
            s.set("timeout", global_params.TIMEOUT)
            s.add(terminal["path_condition"])
            s.add(message_value > 0)
            if s.check() == sat:
                money_flow_in = True

    # Check if money could potentially go out
    money_flow_out = False
    if suicidal:
        money_flow_out = True
    else:
        for index in list_of_calls:
            for call in list_of_calls[index]:
                if call["type"] == "DELEGATECALL":
                    money_flow_out = True
                elif call["type"] == "CALL" and is_expr(call["value"]) or call["value"] > 0:
                    money_flow_out = True

    if money_flow_in and money_flow_out:
        heuristic = {}
        heuristic["function_signature"] = None
        heuristic["block"]              = None
        heuristic["type"]               = HeuristicTypes.MONEY_FLOW
        heuristic["pc"]                 = None
        if not heuristic in heuristics:
            heuristics.append(heuristic)
        return True
    return False

########################################################
#                  H1: Balance Disorder                #
########################################################
def detect_balance_disorder():
    for index in list_of_calls:
        for call in list_of_calls[index]:
            if call["block"] in infeasible_blocks and is_expr(call["value"]) and ("balance_Ia + Iv" == str(call["value"]) or "Iv + balance_Ia" == str(call["value"])):
                heuristic = {}
                heuristic["function_signature"] = call["function_signature"]
                heuristic["block"]              = call["block"]
                heuristic["type"]               = HeuristicTypes.BALANCE_DISORDER
                heuristic["pc"]                 = call["pc"]
                if not heuristic in heuristics:
                    heuristics.append(heuristic)

########################################################
#                  H2: Hidden Transfer                 #
########################################################
def detect_hidden_transfer():
    for i in list_of_calls:
        for call1 in list_of_calls[i]:
            for j in list_of_calls:
                for call2 in list_of_calls[j]:
                    if i < j and call1["pc"] < call2["pc"] \
                    and not call1["recipient"] == call2["recipient"] \
                    and str(call1["value"]) == str(account_balance) \
                    and str(call2["value"]) == str(account_balance) \
                    and call1["pc"] in execution_paths[j] \
                    and call2["pc"] in execution_paths[j] \
                    and "Ia_store" in str(call1["recipient"]) \
                    and "Is" in str(call2["recipient"]):
                        heuristic = {}
                        heuristic["function_signature"] = call1["function_signature"]
                        heuristic["block"]              = call1["block"]
                        heuristic["type"]               = HeuristicTypes.HIDDEN_TRANSFER
                        heuristic["pc"]                 = call1["pc"]
                        if not heuristic in heuristics:
                            heuristics.append(heuristic)

########################################################
#               H3: Inheritance Disorder               #
########################################################
def detect_inheritance_disorder():
    owner_storage_addresses = []
    for index in list_of_calls:
        for call in list_of_calls[index]:
            if call["input_size"] == 0 and is_expr(call["value"]):
                for condition in call["path_condition"]:
                    if is_expr(condition) and "==" in str(condition):
                        separated_condition = remove_line_break_space(simplify(condition)).split("==")
                        if (("Ia_store" in separated_condition[0] or "0" in separated_condition[0]) and "Is" in separated_condition[1]) \
                        or (("Ia_store" in separated_condition[1] or "0" in separated_condition[1]) and "Is" in separated_condition[0]):
                            matches = re.compile("Ia_store_([0-9]+)\)").findall(remove_line_break_space(condition))
                            if matches and not matches[0] in owner_storage_addresses:
                                owner_storage_addresses.append(matches[0])
    if owner_storage_addresses:
        message_value_sstores = []
        for sstore in list_of_sstores:
            if "Iv" in str(sstore["value"]):
                if not sstore["variable"] in message_value_sstores:
                    message_value_sstores.append(sstore["variable"])
        message_sender_sstores = []
        for sstore in list_of_sstores:
            if str(sstore["address"]).isdigit():
                if "Is" in str(sstore["value"]):
                    variables = []
                    for condition in sstore["path_condition"]:
                        if is_expr(condition):
                            for var in get_vars(condition):
                                if not str(var) in variables:
                                    variables.append(str(var))
                        if "Iv" in str(condition) and "Ia_store" in str(condition):
                            if not sstore in message_sender_sstores:
                                message_sender_sstores.append(sstore)
                    # Check if variables are identical to constructor variables
                    if set(variables) == set(['Iv', 'init_Is', 'init_Ia', 'Id_size', 'Id_1']):
                        message_sender_sstores.append(sstore)
                if "Extract(159, 0, Id_" in str(sstore["value"]):
                    for condition in sstore["path_condition"]:
                        if is_expr(condition):
                            for var in message_value_sstores:
                                if var in get_vars(condition):
                                    message_sender_sstores.append(sstore)
        # Check that message sender is not used in calls
        for sstore in message_sender_sstores:
            used = False
            for sstore_2 in list_of_sstores:
                if str(sstore["address"]) in str(sstore_2["variable"]) and sstore_2["function_signature"] != sstore["function_signature"]:
                    used = True
                    break
            for comparison in list_of_comparisons:
                if is_expr(comparison) and sstore["variable"] in get_vars(comparison):
                    used = True
                    break
            for index in list_of_calls:
                for call in list_of_calls[index]:
                    if sstore["function_signature"] == call["function_signature"]:
                        used = True
                        break
                    if is_expr(call["recipient"]) and sstore["variable"] in get_vars(call["recipient"]):
                        used = True
                        break
                if used:
                    break
            for suicide in list_of_suicides:
                if sstore["function_signature"] == suicide["function_signature"]:
                    used = True
                    break
            if not used:
                # Check that the message sender is not stored in owner location
                if not sstore["address"] in owner_storage_addresses:
                    heuristic = {}
                    heuristic["function_signature"] = sstore["function_signature"]
                    heuristic["block"]              = sstore["block"]
                    heuristic["type"]               = HeuristicTypes.INHERITANCE_DISORDER
                    heuristic["pc"]                 = sstore["pc"]
                    if not heuristic in heuristics:
                        heuristics.append(heuristic)

########################################################
#               H4: Uninitialised Structs              #
########################################################
def detect_uninitialised_structs():
    list_of_relevant_sstores = []
    for struct in list_of_structs:
        for sstore in list_of_sstores:
            if struct["pc"] == sstore["pc"]:
                if not sstore in list_of_relevant_sstores:
                    list_of_relevant_sstores.append(sstore)
    for sstore in list_of_relevant_sstores:
        for index in list_of_calls:
            for call in list_of_calls[index]:
                for condition in call["path_condition"]:
                    if "Is" in str(call["recipient"]) and str(call["value"]) == "balance_Ia" and is_expr(condition) and sstore["variable"] in get_vars(condition):
                        heuristic = {}
                        heuristic["function_signature"] = sstore["function_signature"]
                        heuristic["block"]              = sstore["block"]
                        heuristic["type"]               = HeuristicTypes.UNINITIALISED_STRUCT
                        heuristic["pc"]                 = sstore["pc"]
                        if not heuristic in heuristics:
                            heuristics.append(heuristic)
                if call["value"] == sstore["value"] and (is_expr(call["value"]) or call["value"] > 0):
                    heuristic = {}
                    heuristic["function_signature"] = sstore["function_signature"]
                    heuristic["block"]              = sstore["block"]
                    heuristic["type"]               = HeuristicTypes.UNINITIALISED_STRUCT
                    heuristic["pc"]                 = sstore["pc"]
                    if not heuristic in heuristics:
                        heuristics.append(heuristic)
        for suicide in list_of_suicides:
            for condition in suicide["path_condition"]:
                if is_expr(condition) and sstore["variable"] in get_vars(condition):
                    heuristic = {}
                    heuristic["function_signature"] = sstore["function_signature"]
                    heuristic["block"]              = sstore["block"]
                    heuristic["type"]               = HeuristicTypes.UNINITIALISED_STRUCT
                    heuristic["pc"]                 = sstore["pc"]
                    if not heuristic in heuristics:
                        heuristics.append(heuristic)

########################################################
#              H5: Type Deduction Overflow             #
########################################################
def detect_type_deduction_overflow():
    s = Solver()
    s.set("timeout", global_params.TIMEOUT)
    for index in list_of_calls:
        for call in list_of_calls[index]:
            if "Is" in str(call["recipient"]) and call["input_size"] == 0 and not is_expr(call["value"]) and call["value"] > 0:
                for mul_pc in list_of_multiplications:
                    if mul_pc < call["pc"]:
                        for var_pc in list_of_vars:
                            if mul_pc == var_pc-3:
                                if call["value"] in list_of_multiplications[mul_pc] \
                                and call["value"] in list_of_vars[var_pc]:
                                    heuristic = {}
                                    heuristic["function_signature"] = call["function_signature"]
                                    heuristic["block"]              = call["block"]
                                    heuristic["type"]               = HeuristicTypes.TYPE_DEDUCTION_OVERFLOW
                                    heuristic["pc"]                 = mul_pc
                                    if not heuristic in heuristics:
                                        heuristics.append(heuristic)
                for add_pc in list_of_additions:
                    for var_pc in list_of_vars:
                        if add_pc < var_pc < call["pc"]:
                            if call["value"] in list_of_additions[add_pc] \
                            and call["value"] in list_of_vars[var_pc]:
                                path_conditions = copy.deepcopy(call["path_condition"])
                                if False in path_conditions:
                                    path_conditions.remove(False)
                                s.reset()
                                s.add(path_conditions)
                                s.add(message_value > 0)
                                s.add(message_value != 0)
                                if s.check() == sat:
                                    heuristic = {}
                                    heuristic["function_signature"] = call["function_signature"]
                                    heuristic["block"]              = call["block"]
                                    heuristic["type"]               = HeuristicTypes.TYPE_DEDUCTION_OVERFLOW
                                    heuristic["pc"]                 = add_pc
                                    if not heuristic in heuristics:
                                        heuristics.append(heuristic)

########################################################
#             H6: Skip Empty String Literal            #
########################################################
def detect_skip_empty_string_literal():
    for index in list_of_calls:
        for call in list_of_calls[index]:
            if isReal(call["input_size"]) and call["input_size"] > 0 and is_expr(call["recipient"]) and any([True for var in get_vars(call["recipient"]) if str(var) == "Ia"]):
                if call["input_offset"] in call["memory"]:
                    function_signature = call["memory"][call["input_offset"]]/26959946667150639794667015087019630673637144422540572481103610249216L
                    if function_signature in list_of_functions and len(list_of_functions[function_signature]) != call["input_size"]/32:
                        for index2 in list_of_calls:
                            for call2 in list_of_calls[index2]:
                                if function_signature == call2["function_signature"]:
                                    if call2["type"] == "CALL" and call2["input_size"] == 0 and "Id_" in str(call2["recipient"]):
                                        heuristic = {}
                                        heuristic["function_signature"] = call2["function_signature"]
                                        heuristic["block"]              = call2["block"]
                                        heuristic["type"]               = HeuristicTypes.SKIP_EMPTY_STRING_LITERAL
                                        heuristic["pc"]                 = call2["pc"]
                                        if not heuristic in heuristics:
                                            heuristics.append(heuristic)

########################################################
#                H7: Hidden State Update               #
########################################################
def detect_hidden_state_update():
    for index in list_of_calls:
        for call in list_of_calls[index]:
            if call["input_size"] == 0 and "Is" in str(call["recipient"]) and (isReal(call["value"]) or str(call["value"]) == "balance_Ia"):
                new_path_conditions = []
                for condition in call["path_condition"]:
                    if not any(value in str(condition) for value in ["balance_Ia > 0", "balance_Ia == balance_Ia + Iv"]):
                        new_path_conditions.append(condition)
                s = Solver()
                s.set("timeout", global_params.TIMEOUT)
                s.add(new_path_conditions)
                if s.check() == sat:
                    check_if_path_conditions_depend_on_storage(call, [], 0)

def get_function_signature_from_path_condition(path_condition):
    for condition in path_condition:
        if is_expr(condition) and str(condition).startswith("If(Extract(255, 224, Id_1) == "):
            match = re.compile("Extract\(255, 224, Id_1\) == ([0-9]+)").findall(str(condition))
            if match:
                return int(match[0])
    return None

def extract_storage_location_range(condition, variable):
    if is_expr(condition):
        matches = re.compile("Extract\((.+?), (.+?), "+str(variable)+"\)").findall(str(simplify(condition)))
        if matches:
            return matches[0]
    return None

def check_if_path_conditions_depend_on_storage(origin, visitedx, depth):
    message_value_comparison = []
    for condition in origin["path_condition"]:
        if "Iv" in str(condition) and not any(value in str(condition) for value in ["Iv >= 0", "init_Is >= Iv", "balance_Ia == balance_Ia + Iv", "init_Ia + Iv", "If(Iv == 0, 1, 0) != 0"]):
            message_value_comparison.append(condition)
    s = Solver()
    s.set("timeout", global_params.TIMEOUT)
    if message_value_comparison:
        if not any([True for comparison in message_value_comparison if is_expr(comparison) and any([True for var in get_vars(comparison) if not "Iv" == str(var) and not "Ia_store_" in str(var)])]):
            for condition in origin["path_condition"]:
                if "Ia_store" in str(condition) and not "Iv" in str(condition):
                    for var in get_vars(condition):
                        if str(var).startswith("Ia_store"):
                            storage_location_range = extract_storage_location_range(condition, var)
                            visited_pcs = []
                            for sstore in list_of_sstores:
                                if not sstore["pc"] in visited_pcs and sstore["function_signature"] != origin["function_signature"]:
                                    if sstore["variable"] == var and isReal(sstore["address"]) and isSymbolic(sstore["value"]) and any([True for var in get_vars(sstore["value"]) if "Id_" in str(var) or "Ia_store_" in str(var)]):
                                        if storage_location_range == None:
                                            if not any([True for path_condition in sstore["path_condition"] if is_expr(path_condition) and sstore["variable"] in get_vars(path_condition)]):
                                                s.reset()
                                                message_value_path_conditions = []
                                                for condition in sstore["path_condition"]:
                                                    if "Iv" in str(condition):
                                                        message_value_path_conditions.append(condition)
                                                s.add(message_value_path_conditions)
                                                s.add(message_value == 0)
                                                if s.check() == sat:
                                                    s.reset()
                                                    s.add(origin["path_condition"])
                                                    s.add(sstore["variable"] == sstore["value"])
                                                    if s.check() == unsat:
                                                        visited_pcs.append(sstore["pc"])
                                                        heuristic = {}
                                                        heuristic["function_signature"] = sstore["function_signature"]
                                                        heuristic["block"]              = sstore["block"]
                                                        heuristic["type"]               = HeuristicTypes.HIDDEN_STATE_UPDATE
                                                        heuristic["pc"]                 = sstore["pc"]
                                                        if not heuristic in heuristics:
                                                            heuristics.append(heuristic)
                                        else:
                                            if not any([True for path_condition in sstore["path_condition"] if storage_location_range == extract_storage_location_range(path_condition, sstore["variable"])]):
                                                s.reset()
                                                message_value_path_conditions = []
                                                for condition in sstore["path_condition"]:
                                                    if "Iv" in str(condition):
                                                        message_value_path_conditions.append(condition)
                                                s.add(message_value_path_conditions)
                                                s.add(message_value == 0)
                                                if s.check() == sat:
                                                    s.reset()
                                                    s.add(origin["path_condition"])
                                                    s.add(sstore["variable"] == sstore["value"])
                                                    if s.check() == unsat:
                                                        visited_pcs.append(sstore["pc"])
                                                        heuristic = {}
                                                        heuristic["function_signature"] = sstore["function_signature"]
                                                        heuristic["block"]              = sstore["block"]
                                                        heuristic["type"]               = HeuristicTypes.HIDDEN_STATE_UPDATE
                                                        heuristic["pc"]                 = sstore["pc"]
                                                        if not heuristic in heuristics:
                                                            heuristics.append(heuristic)
    else:
        for condition_1 in origin["path_condition"]:
            if "Ia_store" in str(condition_1):
                for var_1 in get_vars(condition_1):
                    if str(var_1).startswith("Ia_store"):
                        visited_pcs = []
                        for sstore_1 in list_of_sstores:
                            if not sstore_1["pc"] in visited_pcs and sstore_1["function_signature"] != origin["function_signature"]:
                                if sstore_1["variable"] == var_1 and isReal(sstore_1["address"]) and isSymbolic(sstore_1["value"]) and any([True for var in get_vars(sstore_1["value"]) if "Id_" in str(var) or "Ia_store_" in str(var)]):
                                    s.reset()
                                    s.add(sstore_1["path_condition"])
                                    s.add(message_value > 0)
                                    s.add(message_value != 0)
                                    if s.check() == sat:
                                        visited_pcs.append(sstore_1["pc"])
                                        for condition_2 in sstore_1["path_condition"]:
                                            if "Ia_store" in str(condition_2):
                                                for var_2 in get_vars(condition_2):
                                                    if str(var_2).startswith("Ia_store"):
                                                        for sstore_2 in list_of_sstores:
                                                            if not sstore_2["pc"] in visited_pcs and sstore_2["function_signature"] != sstore_1["function_signature"] and sstore_2["function_signature"] != origin["function_signature"]:
                                                                if sstore_2["variable"] == var_2 and isReal(sstore_2["address"]) and is_expr(sstore_2["value"]) and any([True for var in get_vars(sstore_2["value"]) if "Id_" in str(var) or "Ia_store_" in str(var)]):
                                                                    s.reset()
                                                                    message_value_path_conditions = []
                                                                    for condition in sstore_2["path_condition"]:
                                                                        if "Iv" in str(condition):
                                                                            message_value_path_conditions.append(condition)
                                                                    s.add(message_value_path_conditions)
                                                                    s.add(message_value == 0)
                                                                    if s.check() == sat:
                                                                        s.reset()
                                                                        s.add(sstore_1["path_condition"])
                                                                        s.add(sstore_2["variable"] == sstore_2["value"])
                                                                        if s.check() == unsat:
                                                                            visited_pcs.append(sstore_2["pc"])
                                                                            heuristic = {}
                                                                            heuristic["function_signature"] = sstore_2["function_signature"]
                                                                            heuristic["block"]              = sstore_2["block"]
                                                                            heuristic["type"]               = HeuristicTypes.HIDDEN_STATE_UPDATE
                                                                            heuristic["pc"]                 = sstore_2["pc"]
                                                                            if not heuristic in heuristics:
                                                                                heuristics.append(heuristic)

########################################################
#                 H8: Straw Man Contract               #
########################################################
def detect_straw_man_contract():
    call_pcs = []
    for index in list_of_calls:
        for call in list_of_calls[index]:
            if not call["pc"] in call_pcs:
                call_pcs.append(call["pc"])
    for index in list_of_calls:
        for call in list_of_calls[index]:
            if call["type"] == "CALL" and (is_expr(call["value"]) or call["value"] > 0) and ("Id_" in str(call["recipient"]) or "Is" in str(call["recipient"])) and call["input_size"] == 0:
                for index2 in list_of_calls:
                    for call2 in list_of_calls[index2]:
                        if call["pc"] != call2["pc"] \
                        and call["function_signature"] == call2["function_signature"] \
                        and str(call["recipient"]) != str(call2["recipient"]) \
                        and "Ia_store_" in str(call2["recipient"]) \
                        and (is_expr(call2["input_size"]) or call2["input_size"] > 0) \
                        and any([True for index in execution_paths if call["pc"] in execution_paths[index] and call2["pc"] in execution_paths[index] and len(list(set(call_pcs) & set(execution_paths[index]))) == 2]) \
                        and all(condition in call2["path_condition"] for condition in call["path_condition"]):
                            if call2["type"] == "DELEGATECALL" and call["pc"] > call2["pc"] and str(call["value"]) == str(account_balance) and ("Is" in str(call["recipient"]) or "Id" in str(call["recipient"])):
                                message_value_path_conditions = []
                                for condition in call["path_condition"]:
                                    if "Iv" in str(condition):
                                        message_value_path_conditions.append(condition)
                                message_value_path_conditions2 = []
                                for condition in call2["path_condition"]:
                                    if "Iv" in str(condition):
                                        message_value_path_conditions2.append(condition)
                                if any([True for condition in message_value_path_conditions if "Iv" in str(condition) and "Ia_store" in str(condition)]) \
                                and any([True for condition in message_value_path_conditions2 if "Iv" in str(condition) and "Ia_store" in str(condition)]):
                                    heuristic = {}
                                    heuristic["function_signature"] = call2["function_signature"]
                                    heuristic["block"]              = call2["block"]
                                    heuristic["type"]               = HeuristicTypes.STRAW_MAN_CONTRACT
                                    heuristic["pc"]                 = call2["pc"]
                                    if not heuristic in heuristics:
                                        heuristics.append(heuristic)
                            if call2["type"] == "CALL" and call["pc"] < call2["pc"] and not "2300" in str(call["gas"]) and call["input_size"] == 0 and not is_expr(call2["input_size"]) and any([True for i in range(call2["input_size"]/32) if call2["input_offset"]+4+i*32 in call2["memory"] and "Is" in str(call2["memory"][call2["input_offset"]+4+i*32])]):
                                heuristic = {}
                                heuristic["function_signature"] = call2["function_signature"]
                                heuristic["block"]              = call2["block"]
                                heuristic["type"]               = HeuristicTypes.STRAW_MAN_CONTRACT
                                heuristic["pc"]                 = call2["pc"]
                                if not heuristic in heuristics:
                                    heuristics.append(heuristic)

def detect_honeypots():
    if detect_cash_flow():
        if global_params.DEBUG_MODE:
            log.info("\t--------- Begin Time ---------")
            start_time = time.time()
        detect_balance_disorder()
        if global_params.DEBUG_MODE:
            elapsed_time = time.time() - start_time
            log.info("\t Balance disorder: \t "+str(math.ceil(elapsed_time))+" seconds")
            start_time = time.time()
        detect_hidden_transfer()
        if global_params.DEBUG_MODE:
            elapsed_time = time.time() - start_time
            log.info("\t Hidden transfer: \t "+str(math.ceil(elapsed_time))+" seconds")
            start_time = time.time()
        detect_inheritance_disorder()
        if global_params.DEBUG_MODE:
            elapsed_time = time.time() - start_time
            log.info("\t Inheritance disorder: \t "+str(math.ceil(elapsed_time))+" seconds")
            start_time = time.time()
        detect_uninitialised_structs()
        if global_params.DEBUG_MODE:
            elapsed_time = time.time() - start_time
            log.info("\t Uninitialised structs:  "+str(math.ceil(elapsed_time))+" seconds")
            start_time = time.time()
        detect_type_deduction_overflow()
        if global_params.DEBUG_MODE:
            elapsed_time = time.time() - start_time
            log.info("\t Type overflow: \t "+str(math.ceil(elapsed_time))+" seconds")
            start_time = time.time()
        detect_skip_empty_string_literal()
        if global_params.DEBUG_MODE:
            elapsed_time = time.time() - start_time
            log.info("\t Skip empty string: \t "+str(math.ceil(elapsed_time))+" seconds")
            start_time = time.time()
        detect_hidden_state_update()
        if global_params.DEBUG_MODE:
            elapsed_time = time.time() - start_time
            log.info("\t Hidden state update: \t "+str(math.ceil(elapsed_time))+" seconds")
            start_time = time.time()
        detect_straw_man_contract()
        if global_params.DEBUG_MODE:
            elapsed_time = time.time() - start_time
            log.info("\t Straw man contract: \t "+str(math.ceil(elapsed_time))+" seconds")
            log.info("\t---------- End Time ----------")

    money_flow_found                = any([HeuristicTypes.MONEY_FLOW                in heuristic["type"] for heuristic in heuristics])
    balance_disorder_found          = any([HeuristicTypes.BALANCE_DISORDER          in heuristic["type"] for heuristic in heuristics])
    hidden_transfer_found           = any([HeuristicTypes.HIDDEN_TRANSFER           in heuristic["type"] for heuristic in heuristics])
    inheritance_disorder_found      = any([HeuristicTypes.INHERITANCE_DISORDER      in heuristic["type"] for heuristic in heuristics])
    uninitialised_struct_found      = any([HeuristicTypes.UNINITIALISED_STRUCT      in heuristic["type"] for heuristic in heuristics])
    type_deduction_overflow_found   = any([HeuristicTypes.TYPE_DEDUCTION_OVERFLOW   in heuristic["type"] for heuristic in heuristics])
    skip_empty_string_literal_found = any([HeuristicTypes.SKIP_EMPTY_STRING_LITERAL in heuristic["type"] for heuristic in heuristics])
    hidden_state_update_found       = any([HeuristicTypes.HIDDEN_STATE_UPDATE       in heuristic["type"] for heuristic in heuristics])
    straw_man_contract_found        = any([HeuristicTypes.STRAW_MAN_CONTRACT        in heuristic["type"] for heuristic in heuristics])

    if source_map:
        # Money flow
        results["money_flow"] = money_flow_found
        s = "\t Money flow:    \t "+str(money_flow_found)
        log.info(s)
        # Balance disorder
        pcs = [heuristic["pc"] for heuristic in heuristics if HeuristicTypes.BALANCE_DISORDER in heuristic["type"]]
        pcs = [pc for pc in pcs if source_map.find_source_code(pc)]
        pcs = source_map.reduce_same_position_pcs(pcs)
        s = source_map.to_str(pcs, "Balance disorder")
        if s:
            results["balance_disorder"] = s
        s = "\t Balance disorder: \t "+str(balance_disorder_found) + s
        log.info(s)
        # Hidden transfer
        pcs = [heuristic["pc"] for heuristic in heuristics if HeuristicTypes.HIDDEN_TRANSFER in heuristic["type"]]
        pcs = [pc for pc in pcs if source_map.find_source_code(pc)]
        pcs = source_map.reduce_same_position_pcs(pcs)
        s = source_map.to_str(pcs, "Hidden transfer")
        if s:
            results["hidden_transfer"] = s
        s = "\t Hidden transfer: \t "+str(hidden_transfer_found) + s
        log.info(s)
        # Inheritance disorder
        pcs = [heuristic["pc"] for heuristic in heuristics if HeuristicTypes.INHERITANCE_DISORDER in heuristic["type"]]
        pcs = [pc for pc in pcs if source_map.find_source_code(pc)]
        pcs = source_map.reduce_same_position_pcs(pcs)
        s = source_map.to_str(pcs, "Inheritance disorder")
        if s:
            results["inheritance_disorder"] = s
        s = "\t Inheritance disorder: \t "+str(inheritance_disorder_found) + s
        log.info(s)
        # Uninitialised struct
        pcs = [heuristic["pc"] for heuristic in heuristics if HeuristicTypes.UNINITIALISED_STRUCT in heuristic["type"]]
        pcs = [pc for pc in pcs if source_map.find_source_code(pc)]
        pcs = source_map.reduce_same_position_pcs(pcs)
        s = source_map.to_str(pcs, "Uninitialised struct")
        if s:
            results["uninitialised_struct"] = s
        s = "\t Uninitialised struct: \t "+str(uninitialised_struct_found) + s
        log.info(s)
        # Type deduction overflow
        pcs = [heuristic["pc"] for heuristic in heuristics if HeuristicTypes.TYPE_DEDUCTION_OVERFLOW in heuristic["type"]]
        pcs = [pc for pc in pcs if source_map.find_source_code(pc)]
        pcs = source_map.reduce_same_position_pcs(pcs)
        s = source_map.to_str(pcs, "Type deduction overflow")
        if s:
            results["type_deduction_overflow"] = s
        s = "\t Type overflow: \t "+str(type_deduction_overflow_found) + s
        log.info(s)
        # Skip empty string literal
        pcs = [heuristic["pc"] for heuristic in heuristics if HeuristicTypes.SKIP_EMPTY_STRING_LITERAL in heuristic["type"]]
        pcs = [pc for pc in pcs if source_map.find_source_code(pc)]
        pcs = source_map.reduce_same_position_pcs(pcs)
        s = source_map.to_str(pcs, "Skip empty string literal")
        if s:
            results["skip_empty_string_literal"] = s
        s = "\t Skip empty string: \t "+str(skip_empty_string_literal_found) + s
        log.info(s)
        # Hidden State Update
        pcs = [heuristic["pc"] for heuristic in heuristics if HeuristicTypes.HIDDEN_STATE_UPDATE in heuristic["type"]]
        pcs = [pc for pc in pcs if source_map.find_source_code(pc)]
        pcs = source_map.reduce_same_position_pcs(pcs)
        s = source_map.to_str(pcs, "Hidden state update")
        if s:
            results["hidden_state_update"] = s
        s = "\t Hidden state update: \t "+str(hidden_state_update_found) + s
        log.info(s)
        # Straw Man Contract
        pcs = [heuristic["pc"] for heuristic in heuristics if HeuristicTypes.STRAW_MAN_CONTRACT in heuristic["type"]]
        pcs = [pc for pc in pcs if source_map.find_source_code(pc)]
        pcs = source_map.reduce_same_position_pcs(pcs)
        s = source_map.to_str(pcs, "Straw man contract")
        if s:
            results["straw_man_contract"] = s
        s = "\t Straw man contract: \t "+str(straw_man_contract_found) + s
        log.info(s)
    else:
        # Money flow
        results["money_flow"] = money_flow_found
        s = "\t Money flow:    \t "+str(money_flow_found)
        log.info(s)
        # Balance disorder
        results["balance_disorder"] = balance_disorder_found
        s = "\t Balance disorder: \t "+str(balance_disorder_found)
        log.info(s)
        # Hidden transfer
        results["hidden_transfer"] = hidden_transfer_found
        s = "\t Hidden transfer: \t "+str(hidden_transfer_found)
        log.info(s)
        # Inheritance disorder
        results["inheritance_disorder"] = inheritance_disorder_found
        s = "\t Inheritance disorder: \t "+str(inheritance_disorder_found)
        log.info(s)
        # Uninitialised struct
        results["uninitialised_struct"] = uninitialised_struct_found
        s = "\t Uninitialised struct: \t "+str(uninitialised_struct_found)
        log.info(s)
        # Type deduction overflow
        results["type_deduction_overflow"] = type_deduction_overflow_found
        s = "\t Type overflow: \t "+str(type_deduction_overflow_found)
        log.info(s)
        # Skip empty string literal
        results["skip_empty_string_literal"] = skip_empty_string_literal_found
        s = "\t Skip empty string: \t "+str(skip_empty_string_literal_found)
        log.info(s)
        # Hidden state update
        results["hidden_state_update"] = hidden_state_update_found
        s = "\t Hidden state update: \t "+str(hidden_state_update_found)
        log.info(s)
        # Straw man contract
        results["straw_man_contract"] = straw_man_contract_found
        s = "\t Straw man contract: \t "+str(straw_man_contract_found)
        log.info(s)

def detect_bugs():
    global results
    global g_timeout
    global source_map
    global visited_pcs

    if global_params.DEBUG_MODE:
        print "Number of total paths: "+str(total_no_of_paths)
        print ""

    if instructions:
        evm_code_coverage = float(len(visited_pcs)) / len(instructions.keys()) * 100
        log.info("\t EVM code coverage: \t %s%%", round(evm_code_coverage, 1))
        results["evm_code_coverage"] = str(round(evm_code_coverage, 1))

        dead_code = list(set(instructions.keys()) - set(visited_pcs))
        for pc in dead_code:
            results["dead_code"].append(instructions[pc])

        detect_honeypots()

        stop_time = time.time()
        results["execution_time"] = str(stop_time-start_time)
        log.info("\t --- "+str(stop_time - start_time)+" seconds ---")

        results["execution_paths"] = str(total_no_of_paths)
        results["timeout"] = g_timeout
    else:
        log.info("\t EVM code coverage: \t 0.0")
        log.info("\t Money flow: \t False")
        log.info("\t Balance disorder: \t False")
        log.info("\t Hidden transfer: \t False")
        log.info("\t Inheritance disorder: \t False")
        log.info("\t Uninitialised struct: \t False")
        log.info("\t Type overflow: \t False")
        log.info("\t Skip empty string: \t False")
        log.info("\t Hidden state update: \t False")
        log.info("\t Straw man contract: \t False")
        log.info("\t  --- 0.0 seconds ---")
        results["evm_code_coverage"] = "0.0"
        results["execution_paths"] = str(total_no_of_paths)
        results["timeout"] = g_timeout

    if len(heuristics) > 0:
        for heuristic in heuristics:
            if heuristic["function_signature"]:
                if heuristic["function_signature"]:
                    method = "{0:#0{1}x}".format(heuristic["function_signature"], 10)
                else:
                    method = ""
                if not method in results["attack_methods"]:
                    results["attack_methods"].append(method)
        for index in list_of_calls:
            for call in list_of_calls[index]:
                if call["type"] == "CALL" and call["input_size"] == 0:
                    if call["function_signature"]:
                        method = "{0:#0{1}x}".format(call["function_signature"], 10)
                    else:
                        method = ""
                    if not method in results["cashout_methods"]:
                        results["cashout_methods"].append(method)

def closing_message():
    global c_name
    global results

    log.info("\t====== Analysis Completed ======")
    if global_params.STORE_RESULT:
        result_file = os.path.join(global_params.RESULTS_DIR, c_name+'.json'.split('/')[-1])
        if '.sol' in c_name:
            result_file = os.path.join(global_params.RESULTS_DIR, c_name.split(':')[0].replace('.sol', '.json').split('/')[-1])
        elif '.bin.evm.disasm' in c_name:
            result_file = os.path.join(global_params.RESULTS_DIR, c_name.replace('.bin.evm.disasm', '.json').split('/')[-1])
        mode = 'a'
        if global_params.BYTECODE:
            mode = 'w'
        if not os.path.isfile(result_file):
            with open(result_file, mode) as of:
                if ':' in c_name:
                    of.write("{")
                    of.write('"'+str(c_name.split(':')[1].replace('.evm.disasm', ''))+'":')
                of.write(json.dumps(results, indent=1))
        else:
            with open(result_file, mode) as of:
                if ':' in c_name:
                    of.write(",")
                    of.write('"'+str(c_name.split(':')[1].replace('.evm.disasm', ''))+'":')
                of.write(json.dumps(results, indent=1))
        log.info("Wrote results to %s.", result_file)

def handler(signum, frame):
    global g_timeout

    print "!!! SYMBOLIC EXECUTION TIMEOUT !!!"
    g_timeout = True
    raise Exception("timeout")

def main(contract, contract_sol, _source_map = None):
    global c_name
    global c_name_sol
    global source_map
    global start_time

    c_name = contract
    c_name_sol = contract_sol
    source_map = _source_map

    initGlobalVars()
    set_cur_file(c_name[4:] if len(c_name) > 5 else c_name)
    start_time = time.time()
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(global_params.GLOBAL_TIMEOUT)

    log.info("Running, please wait...")

    try:
        build_cfg_and_analyze()
        log.debug("Done Symbolic execution")
    except Exception as e:
        if global_params.DEBUG_MODE:
            traceback.print_exc()
        if str(e) == "timeout":
            pass
        else:
            print("Contract: "+str(c_name_sol))
            pass

    if callable(getattr(signal, "alarm", None)):
        signal.alarm(0)

    log.info("\t============ Results ===========")

    detect_bugs()
    closing_message()

if __name__ == '__main__':
    main(sys.argv[1])
