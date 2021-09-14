# IDA Pattern Search
### by [Argus Cyber Security Ltd.](https://argus-sec.com/)
The _IDA Pattern Search_ plugin adds a capability of finding functions according to bit-patterns into the well-known IDA Pro disassembler based on Ghidra’s function patterns format. Using this plugin, it is possible to define new patterns according to the appropriate CPU architecture and analyze the target binary to find and define new functions in it.

For more detailed information, including Ghidra's format for bit-patterns and how to generate new patterns, check out our [blog post](https://argus-sec.com/using-bitfield-patterns-to-identify-functions-in-binaries/) about this plugin.

## Usage

1. Place all repo files under the IDA plugins folder (i.e. &lt;IDA installation dir>\plugins).
2. Start IDA and load the desired program with the appropriate CPU architecture.
3. From the menu, choose: Edit → Plugins → IDA Pattern Search.
4. In case you want the plugin to search for function prologues in all possible undefined code, choose Yes in the displayed message box. However, if you want the plugin to search in specific address ranges or segments, choose No and specify in the next textbox the desired address ranges or segments (format is explained below).

Note that the plugin will identify the CPU architecture and find functions according to the CPU architecture matching patterns residing in the _function_patterns_ folder.

Currently, the supported architectures are ARM/THUMB, AARCH64, PPC, v850. More can be added easily and how to do it is explained below.

It should be noted that the current version uses only post-patterns, as we find those more effective than pre-patterns. While the functionality to use pre-patterns exists in our code, it is currently disabled.


## How to define the target addresses that the plugin will work on?

Target addresses can be specified in two non-exclusive ways using a python dictionary:

1. Address range(s) - either a tuple or a list of tuples specifying a start address and an exclusive end address, passed in the address_ranges argument. Passing an empty list would result in including NO addresses.

    For example:
    ```python
    {"address_ranges":[(0, 0x1000), (0xFFFF0000, 0xFFFFFFFF)]}
    {"address_ranges":(0, 0xFFFFFFFF)}
    ```

2. Segment name(s) - either a segment name or a list of segment names, passed in the segment's argument. Passing an empty list would include all arguments in the IDB.

    For example:
    ```python
    {"segments":[".text", ".bss"]}
    {"segments":".text"}
    {"segments":[]}
    ```

* You can also include both, for example:
    ```python
    {"address_ranges":(0x0, 0xFFFFFFFF),"segments":[".text"]}
    ```

## How to add new CPU architecture?

Simply add the patterns file in the function_patterns directory. This pattern file can be simply taken from Ghidra or created from scratch.

Then, add the matching parameters to the __SEARCH_PARAMETERS_ dictionary defined in the code.

Finally, add to the function _explore_using_patterns_ a code that handles the added CPU architecture and calls _parse_and_search_ function with the newly added __SEARCH_PARAMETERS_ dictionary entry as function arguments.
