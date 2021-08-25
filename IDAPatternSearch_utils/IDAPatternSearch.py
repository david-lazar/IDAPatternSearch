import ida_funcs
import ida_bytes
import idc
import ida_search
import idaapi
import ida_xref
import ida_segment
import ida_offset
import ida_kernwin
from idaapi import BADADDR
from ida_search import SEARCH_DOWN, SEARCH_UP
import ida_auto

import IDAPatternSearch_utils.ida_common as ida_common

import sys
import os
import pathlib
import struct
import ast

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

PATH_TO_FUNCTION_PATTERNS = str(pathlib.Path(
    __file__).parent.absolute()) + "\\function_patterns\\"

# Each dictionary entry should include: (pattern_file_name, use_pre_patterns, use_post_patterns, arch_name, t_register_value=None)
_SEARCH_PARAMETERS = {
    'THUMB_LE_LOOSENED': ("THUMB_LE_LOOSENED.xml", False, True, "THUMB", 1),
    'THUMB_LE': ("THUMB_LE.xml", False, True, "THUMB", 1),
    'THUMB_BE_LOOSENED': ("THUMB_BE_LOOSENED.xml", False, True, "THUMB", 1),
    'THUMB_BE': ("THUMB_BE.xml", False, True, "THUMB", 1),
    'ARM_32_LE': ("ARM_32_LE.xml", False, True, "ARM_32", 0),
    'ARM_32_BE': ("ARM_32_BE.xml", False, True, "ARM_32", 0),
    'AARCH_64_LE': ("AARCH_64_LE.xml", False, True, "AARCH64"),
    'PPC_BE': ("PPC_BE.xml", False, True, "PowerPC"),
    'V850': ("V850.xml", False, True, "V850")
}


# Alt + G
def _change_t_register(ea, val):
    if val == -1:
        return

    idaapi.split_sreg_range(ea, idaapi.str2reg("T"), val, idaapi.SR_user)


def _parse_ghidra_pattern_item(pattern_item, element_length):
    '''
    This function parses a given Ghidra pattern item (pattern_item) which is one item from a Ghidra pattern.
    The function also uses (element_length) to determine if it is: 
        * Hex item (starting with 0x which was already omitted before calling this function)
          which in this case (element_length) == 4
        * Bitfield item
          which in this case (element_length) == 1
    The '.' characther in both item types represents a wildcard Bit/Byte depends on the item type (Hex/Bitfield).
    This function returns two values: (image, mask) 
        * image - represents the item image to search by the pattern.
        * mask -  represents the item mask that can be used to mask out the matched bytes and check against the image
    '''
    cur_image = 0
    cur_mask = 0
    for element in pattern_item:
        if element == '.':
            # Wildcard element
            # mask should be zeros (in bits), image should be zero (lets say 0)
            cur_mask = cur_mask << element_length
            cur_image = cur_image << element_length
        else:
            # mask should be 1's (in bits), image is same as half_byte
            cur_mask = cur_mask << element_length
            if element_length == 1:
                # bit element
                cur_mask += 1
            else:
                # half byte element
                cur_mask += 0xf

            cur_image = cur_image << element_length
            if element_length == 1:
                # bit element
                cur_image += int(element, 2)
            else:
                # half byte element
                cur_image += int(element, 16)
    return cur_image, cur_mask


def _convert_ghidra_pattern_to_image_and_mask(ghidra_pattern):
    '''
    This function parses a given Ghidra pattern (ghidra_pattern) after extracted from the XML file already.
    Every item is parsed and at the end, all the items are joined into 2 returned byte strings: image and mask.
    The function returns a dictionary with the keys:
        * image - represents the image to search by the pattern.
        * mask - represents the mask that can be used to mask out the matched bytes and check against the image
    The values in the dictionary are byte-strings.
    '''
    ghidra_pattern = ghidra_pattern.split()
    image = [b'']*len(ghidra_pattern)
    mask = [b'']*len(ghidra_pattern)
    for i in range(len(ghidra_pattern)):
        pattern_item = ghidra_pattern[i]
        pattern_byte_len = 0  # Number of bytes presetend by pattern
        cur_image = 0  # Image of current pattern item
        cur_mask = 0  # Mask of current pattern item

        if '0x' in pattern_item[0:2]:
            # Hex parsing
            pattern_item = pattern_item[2:]  # Remove '0x' at start
            if len(pattern_item) == 2 or len(pattern_item) == 4 or len(pattern_item) == 8:
                cur_image, cur_mask = _parse_ghidra_pattern_item(
                    pattern_item, 4)

                # 1 or 2 or 4 byte format
                pattern_byte_len = len(pattern_item)//2
            else:
                print("[-] Unrecognized length while parsing: 0x" +
                      str(pattern_item))
                break
        else:
            # Bit parsing
            if len(pattern_item) == 8:
                cur_image, cur_mask = _parse_ghidra_pattern_item(
                    pattern_item, 1)
                # 1 byte format is the only case for bit parsing
                pattern_byte_len = 1
            else:
                print("[-] Unrecognized length while parsing: " +
                      str(pattern_item))
                break

        # Convert from int to bytes
        image[i] = cur_image.to_bytes(pattern_byte_len, byteorder='big')
        mask[i] = cur_mask.to_bytes(pattern_byte_len, byteorder='big')

    # Join image_list and mask_list
    return {"image": b''.join(image), "mask": b''.join(mask)}


def _parse_ghidra_xml_pattern_list(filepath):
    '''
    Parses an Ghidra pattern XML file resides in (filepath).
    This file contains pattern pairs where each pair consits of pre-patterns and post-patterns.
    Pre-patterns should occur before a function start definition (It is usually a function end in the pattern file).
    Post-patterns should occur in a place where a function start should be defined.

    Returns a dictionary contains two keys:
        * pre_patterns
        * post_patterns
    The values are lists where each item is a Ghidra pattern string.

    Note that only one node for each element type (except data) exists in most cases, 
    but the parsing process treats the elements as lists for a more general case.
    '''
    import xml.dom.minidom

    parsed_pre_patterns = []
    parsed_post_patterns = []

    doc = xml.dom.minidom.parse(filepath)
    patternpairs_list = doc.getElementsByTagName("patternpairs")
    for patternpairs_node in patternpairs_list:
        # Parse pre patterns
        prepatterns_list = patternpairs_node.getElementsByTagName(
            'prepatterns')
        for prepatterns_node in prepatterns_list:
            data_list = prepatterns_node.getElementsByTagName('data')
            for data_node in data_list:
                data_value = data_node.firstChild.nodeValue
                parsed_pre_patterns.append(data_value)

        # Parse post patterns
        postpatterns_list = patternpairs_node.getElementsByTagName(
            'postpatterns')
        for postpatterns_node in postpatterns_list:
            data_list = postpatterns_node.getElementsByTagName('data')
            for data_node in data_list:
                data_value = data_node.firstChild.nodeValue
                parsed_post_patterns.append(data_value)
    return {"pre_patterns": parsed_pre_patterns, "post_patterns": parsed_post_patterns}


def _relax_ghidra_mask(mask):
    '''
    In order to use Ghidra patterns in IDA, we need to make the patterns more premissive
    because IDA only allows byte wildcards, while Ghidra patterns involving bits.

    This function returns the premissive mask given a strict (mask) byte string.

    IDA bin_search mask should be composed of \x00 or \x01 bytes, 
    where \x01 means to perform the comparison and \x00 means not tp perform.
    If the strict mask contains zero bit in one of the bytes, this byte should be \x00 in the relaxed mask.
    Else, the byte contains only one bits, and therefore this byte should be \x01 in the relaxed mask.
    '''
    mask_list = list(mask)
    relaxed_mask = [b'\x00' if b != 0xff else b'\x01' for b in mask_list]
    return b''.join(relaxed_mask)


def parse_and_search(pattern_file_name, use_pre_patterns, use_post_patterns, arch_name, t_register_value=None, **kwargs):
    '''
    Find function prologues based on patterns for given architecture and pattern file.
    '''
    pre_patterns = [None]
    post_patterns = [None]

    pattern_list = _parse_ghidra_xml_pattern_list(
        os.path.join(PATH_TO_FUNCTION_PATTERNS, pattern_file_name))

    if use_post_patterns:
        print("[+] Searching using post-patterns ({})".format(arch_name))
        post_patterns = pattern_list['post_patterns']
    if use_pre_patterns:
        print("[+] Searching using pre-patterns ({})".format(arch_name))
        pre_patterns = pattern_list['pre_patterns']

    _prologue_pattern_search(
        pre_patterns, post_patterns, t_register_value, arch_name, **kwargs)


def _prologue_pattern_search(pre_pattern_list, post_pattern_list, t_register_value, arch_name, **kwargs):
    """
    Find functions prologues in range(**kwargs) based on the given pattern list.

    Patterns are seperated into 2 different lists:  (pre_pattern_list,post_pattern_list). 
    * Pre_pattern is before function definition (e.g. filler or other function end), 
    * Post_pattern is the actual function start.

    The function can use only one of the pattern lists. 
    In this case, the other list (the unused one) should be passed as [None] to the function.
    * As for now we will use only Post Patterns (but usage of pre-patterns is already implemented).

    For each pattern in the pattern list, finding bytes matching the pattern and tries to define a function in IDA.
    Uses the (t_register_value) to set the T register accordingly when tries to define a function. 
    """
    defined_counter = 0  # Number of defined functions
    # Go over all search results for a specific pattern
    for addr_range in ida_common.parse_address_ranges(**kwargs):
        start_ea = addr_range[0]
        end_ea = addr_range[1]
        for pre_pattern in pre_pattern_list:
            for post_pattern in post_pattern_list:
                cur_start_ea = start_ea  # restore cur_start_ea
                while(cur_start_ea < end_ea):
                    cursor, defined = _find_next_pattern_bytes_and_define_function(
                        cur_start_ea, pre_pattern, post_pattern, t_register_value, end_ea)
                    if cursor == BADADDR:
                        break
                    defined_counter += defined
                    cur_start_ea = cursor + 1      # Continue to search in next bytes

    print("[+] Total number of {} functions defined: {}".format(arch_name, defined_counter))


def _find_next_pattern_bytes_and_define_function(start_ea, pre_pattern, post_pattern, t_register_value, end_ea=BADADDR):
    """
    Find bytes starting in range (start_ea,end_ea) based on the given (post_pattern) or/and (pre_pattern).

    There are 3 different cases for the function operation:
    * When only post_pattern exists, the function will be defined at the matched bytes location.
    * When only pre_pattern exists, the function will be defined after the matched bytes location.
    * When both pre_pattern and post_pattern exists, the function will be defined after the pre-pattern matched bytes location.

    When there is a match, first sets the T register with the given value (t_register_value).
    Then, tries to define a function in IDA.
    Returns two values: 
       1. The matched address (in case not found: BADADDR).
       2. An integer that indicates if as a result a function was defined successfully (1 -> Success, 0 -> Failed to define).
    """
    defined = 0  # A function was defined eventually?

    pre_pattern_converted = {}  # in case both pre_pattern and post_pattern exists

    if pre_pattern is None:
        pattern = post_pattern
    elif post_pattern is None:
        pattern = pre_pattern
    else:  # Both pre_pattern and post_pattern
        pattern = pre_pattern + " " + post_pattern
        pre_pattern_converted = _convert_ghidra_pattern_to_image_and_mask(
            pre_pattern)

    pattern_converted = _convert_ghidra_pattern_to_image_and_mask(pattern)

    # Assign pre_pattern_converted in case only pre_pattern exists
    if post_pattern is None:
        pre_pattern_converted = pattern_converted

    pattern_image = pattern_converted['image']
    pattern_mask = pattern_converted['mask']
    # mask from Ghidra should be relaxed to suit IDA search
    relaxed_mask = _relax_ghidra_mask(pattern_mask)
    cursor = ida_bytes.bin_search(start_ea, end_ea, pattern_image,
                                  relaxed_mask, idaapi.BIN_SEARCH_FORWARD, idaapi.BIN_SEARCH_NOCASE)
    if cursor == BADADDR:
        return BADADDR, defined

    # Check if strict mask holds (as defined in Ghidra and includes bits)
    matched_bytes = ida_bytes.get_bytes(cursor, len(pattern_mask))
    masked_bytes = b''.join([int.to_bytes(a & b, 1, 'big')
                            for a, b in zip(matched_bytes, pattern_mask)])
    if masked_bytes != pattern_image:  # because wildcard bit are 0's in the image, we don't need to compare here to pattern_image&pattern_mask
        # strict mask doesn't hold. Continue to next match.
        return cursor, defined

    # Increment cursor if pre_pattern exists
    if pre_pattern is not None:
        cursor = cursor + len(pre_pattern_converted['image'])

    # Only operate on unknown bytes or code bytes that are not part of functions (code bytes marked in red on IDA)
    if ida_bytes.is_unknown(ida_bytes.get_flags(cursor)) or (ida_bytes.is_code(ida_bytes.get_flags(cursor)) and ida_funcs.get_func_num(cursor) == -1):
        # Pattern found.
        # Switch to thumb, try to define a function
        # If failed -> Discard changes
        print("[+] Possible function prologue at {}  -> {}".format(hex(cursor),
              hex(ida_bytes.get_dword(cursor))))

        # Save T register old value (in case we will need to restor it)
        if t_register_value != None:
            t_register_old_value = idc.get_sreg(cursor, "T")

            # Change T register
            _change_t_register(cursor, t_register_value)

        # Try to define a function
        if not ida_funcs.add_func(cursor):
            print("[-]        Could not define a function at {}".format(hex(cursor)))

            # If the definition of the func failed and you have remained with code,
            # undo what you did by "U"'ing it
            if ida_bytes.is_code(ida_bytes.get_flags(cursor)):
                # delete all the chunk you've just tried to define
                idc.del_items(cursor, idc.DELIT_EXPAND, 1)

            if t_register_value != None:
                # Restore T register
                _change_t_register(cursor, t_register_old_value)
        else:
            defined = 1
    return cursor, defined


def explore_using_patterns(**kwargs):
    """
    Identifies the current architecture and explore for functions using predefined patterns.
    The predefined patterns interpreted from Ghidra.

    Supports: 
    - THUMB, ARM 32 bit
    - AARCH64 (ARM 64 bit) (only LE is supported).
    - PowerPC (only BE is supported).
    - V850 (V850E1)
    """

    # Make sure function_patterns directory exists
    if not os.path.exists(PATH_TO_FUNCTION_PATTERNS):
        print("[-] function_patterns directory does not exist")
        print("    Please make sure to include the function_patterns directory in path: " +
              str(PATH_TO_FUNCTION_PATTERNS))
        return

    info = idaapi.get_inf_structure()

    # Handle ARM/Thumb
    if info.procname == "ARM" or info.procname == "ARMB":
        # 64 bit architectures
        # Turns out that AARCH64 bit will return true in is_32bit(). So we need to first check for is_64bit().
        if info.is_64bit():
            parse_and_search(*(_SEARCH_PARAMETERS["AARCH_64_LE"]), **kwargs)

        # 32 bit architectures
        else:
            if info.is_be():
                # Big endian
                parse_and_search(*(_SEARCH_PARAMETERS["ARM_32_BE"]), **kwargs)
                parse_and_search(*(_SEARCH_PARAMETERS["THUMB_BE"]), **kwargs)
                parse_and_search(
                    *(_SEARCH_PARAMETERS["THUMB_BE_LOOSENED"]), **kwargs)
            else:
                # Little endian
                parse_and_search(*(_SEARCH_PARAMETERS["ARM_32_LE"]), **kwargs)
                parse_and_search(*(_SEARCH_PARAMETERS["THUMB_LE"]), **kwargs)
                parse_and_search(
                    *(_SEARCH_PARAMETERS["THUMB_LE_LOOSENED"]), **kwargs)

            # _undefine_filler_functions() # Check for filler functions in ARM or THUMB, in case pre-patterns are used.

    # Handle PowerPC
    elif info.procname == "PPC":
        parse_and_search(*(_SEARCH_PARAMETERS["PPC_BE"]), **kwargs)

    # Handle V850
    elif "V850" in info.procname:
        parse_and_search(*(_SEARCH_PARAMETERS["V850"]), **kwargs)

    else:
        print("[-] Unsupported architecture: " + str(info.procname))

    print("[+] Done exploration")


def _undefine_filler_functions():
    '''
    Searching for all functions that were wrongly defined due to filler pattern ("00 00") and contains all zero-bytes.
    These functions will be undefined.
    Currently doesn't give much added value because we don't use the filler pattern "00 00"
    '''
    print("[+] Searching for filler functions")  # Currently filler functions is all zeros functions.

    # Go over all functions
    for func_addr in ida_common.get_function_iterator():
        # Get function bytes and check for all zeros.
        cur_func = ida_funcs.get_func(func_addr)
        func_bytes = ida_bytes.get_bytes(
            cur_func.start_ea, cur_func.end_ea-cur_func.start_ea)
        is_filler_func = True
        for b in func_bytes:
            if b != 0:
                is_filler_func = False
                break

        # If function bytes are only zeros -> undefine_function
        if is_filler_func:
            _undefine_function(cur_func.start_ea, "Zero filler")


def _undefine_function(start_ea, reason):
    '''
    Undefine the function in address (address_ea).
    Also prints the (reason) for the deletion.
    '''
    # Delete all the function code chunk you've defined
    if (idc.del_items(start_ea, idc.DELIT_EXPAND, 1)):
        print("[+] Deleted function at {}. Reason: {}".format(hex(start_ea), reason))


#--------------------------------------------------------------------------
# IDA Plugin Stuff
#--------------------------------------------------------------------------

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return IDAPatternSearchPlugin()

class IDAPatternSearchPlugin(idaapi.plugin_t):

    flags = 0
    comment = "Identifies the current architecture and look for functions prologues in undefined code using Ghidra patterns"
    help = ""
    wanted_name = "IDA Pattern Search"
    wanted_hotkey = ""

    def init(self):
        """
        What happens when the plugin is loaded.
        """

        if sys.version_info[0] <= 2:
            print('[IDA Pattern Search] IDA Pattern Search supports Python 3+, you are using older version.')
            return idaapi.PLUGIN_SKIP

        print("""[IDA Pattern Search] Plugin loaded, use Edit -> Plugins -> IDA Pattern Search to search for functions """)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        Run plugin.
        """

        yn_value = ida_kernwin.ask_yn(1,"Search for function prologues in all possible undefined code?")
        if yn_value == 1:
            explore_using_patterns()
        
        elif yn_value == 0:
            answer = ida_kernwin.ask_str("{\"address_ranges\":(0x0, 0xFFFFFFFF),\"segments\":[\".text\"]}",\
            0,\
            """Please write target addresses.Target addresses can be specified in two non-exclusive ways using a python dictionary:
            1) Address range(s) - either a tuple or a list of tuples specifying 
            a start address and an exclusive end address, passed in the address_ranges argument. 
            Passing an empty list would result in including NO addresses.
            EXAMPLE: {\"address_ranges\":[(0, 0x1000), (0xFFFF0000, 0xFFFFFFFF)]}
            2) Segment name(s) - either a segment name or a list of segment names, 
            passed in the segments argument. Passing an empty list would include all arguments in the IDB.
            EXAMPLE: {\"segments\":[\".text\", \".bss\"]}
            """)
            if answer is not None:
                explore_using_patterns(**(ast.literal_eval(answer)))

    def term(self):
        pass

