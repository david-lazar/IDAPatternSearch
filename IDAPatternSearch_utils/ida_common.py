import ida_segment
import ida_bytes
import ida_name
import idautils
import idaapi
import itertools

ADDRESS_RANGES = "address_ranges"
SEGMENTS = "segments"
FUNCTIONS = "functions"


def normalize_ranges(address_ranges, function_start_list=None):
    """
    Does two things:
    - converts the function start list into a list of address ranges
       spanning their chunks and merges it with the given address
       ranges list
    - changes the resulting address ranges so that no address appears twice
    """

    # merge the function ranges into with the address ranges
    merged_address_ranges = list(address_ranges)
    if function_start_list is not None:
        for function_start in function_start_list:
            # each chunk is a tuple in the form (start, end_exclusive), just
            # how we like it
            for chunk in idautils.Chunks(function_start):
                merged_address_ranges.append(chunk)

    # convert address ranges into a unique form
    # first sort all the ranges according to their start address
    merged_address_ranges.sort(key=lambda t: t[0])

    final_address_ranges = [merged_address_ranges[0]]

    for (current_start, current_end_exclusive) in itertools.islice(merged_address_ranges,
                                                                   1,
                                                                   len(merged_address_ranges)):
        """
        There could be three cases:
        1) the range is contained in the last range - ignore it
        2) the range is partially contained in the last range - extend the last range
        3) the range lies entirely after the last range - append it to the results
        """
        last_start, last_end_exclusive = final_address_ranges[-1]

        if current_start > last_end_exclusive:
            # case (3)
            # note that if current_start == last_end_exclusive the
            # ranges aren't overlapping, but we can still extend
            # the last range and minimize the total number of ranges
            final_address_ranges.append((current_start, current_end_exclusive))
        elif current_end_exclusive > last_end_exclusive:
            # case (2)
            final_address_ranges[-1] = (last_start, current_end_exclusive)
        # else case (1), which we ignore

    return final_address_ranges


def address_range_iterator(address_ranges, filter_in=None):
    for (start, end_exclusive) in address_ranges:
        current_address = start

        while current_address < end_exclusive:
            if filter_in is None or filter_in(current_address):
                yield current_address
            current_address += ida_bytes.get_item_size(current_address)


def function_iterator(address_ranges, filter_in=None):
    for (start, end_exclusive) in address_ranges:
        for function_start in idautils.Functions(start, end_exclusive):
            if filter_in is None or filter_in(function_start):
                yield function_start


def get_segment_name_count():
    """
    Segment names don't have to be unique (they often are, but sometimes aren't).
    This function counts the number of appearances of each segment name.

    :return: a dictionary of segment name -> count
    """
    segment_name_count = {}

    for segment_index in range(ida_segment.get_segm_qty()):
        segment_name = ida_segment.get_segm_name(ida_segment.getnseg(segment_index))

        if segment_name in segment_name_count:
            segment_name_count[segment_name] += 1
        else:
            segment_name_count[segment_name] = 1

    return segment_name_count


# KEEP THIS IN SYNC WITH THE FUNCTIONS BELOW.
TARGET_ADDRESS_USAGE = """Target addresses can be specified in three non-exclusive ways:
1) Address range(s) - either a tuple or a list of tuples specifying a start
   address and an exclusive end address, passed in the address_ranges 
   argument. Passing an empty list would result in including NO addresses.
   
   EXAMPLE: foo(address_ranges=(0xC000, 0x30000))
   EXAMPLE: foo(address_ranges=[(0, 0x1000), (0xFFFF0000, 0xFFFFFFFF)])
   
2) Segment name(s) - either a segment name or a list of segment names, passed
   in the segments argument. Passing an empty list would include all arguments
   in the IDB.
   
   EXAMPLE: foo(segments=['.text', '.bss'])
   EXAMPLE: foo(segments='.text')
   EXAMPLE: foo(segments=[])

3) Function name(s) - either a function name or a list of function names,
   including all the addresses of the items within each function, passed
   in the functions argument. Passing an empty list would include all
   address ranges of all defined functions.
   
   EXAMPLE: foo(functions='my_func_maybe')
   EXAMPLE: foo(functions=["my_strdup", "my_another_strdup", "my_strdup_srsly_stop"])
   EXAMPLE: foo(functions=[])
   
Passing no arguments at all is equivalent to passing segments=[], i.e. all defined
addresses in the IDB.


   The functions return a single iterator that iterates over the specified
   ranges exactly once.
"""


def get_iterator_usage():
    return TARGET_ADDRESS_USAGE


def parse_address_ranges(**kwargs):
    if ((ADDRESS_RANGES not in kwargs or kwargs[ADDRESS_RANGES] is None) and
            (SEGMENTS not in kwargs or kwargs[SEGMENTS] is None) and
            (FUNCTIONS not in kwargs or kwargs[FUNCTIONS] is None)):
        # default is to iterate over all the segments
        kwargs[SEGMENTS] = []

    final_ranges = []
    function_start_list = []

    if ADDRESS_RANGES in kwargs and kwargs[ADDRESS_RANGES] is not None:
        address_ranges = kwargs[ADDRESS_RANGES]

        if (type(address_ranges) == tuple and
                len(address_ranges) == 2 and
                type(address_ranges[0]) == type(address_ranges[1]) == int):
            # lazy user didn't wrap a single range in an iterable
            address_ranges = [address_ranges]

        for (start, end) in address_ranges:
            final_ranges.append((start, end))

    if SEGMENTS in kwargs and kwargs[SEGMENTS] is not None:
        segments = kwargs[SEGMENTS]

        if not hasattr(segments, '__iter__'):
            # lazy user didn't wrap a single segment in an iterable
            segments = [segments]

        if len(segments) == 0:
            # all the segments
            for segment_index in range(ida_segment.get_segm_qty()):
                segment = ida_segment.getnseg(segment_index)
                final_ranges.append((segment.start_ea, segment.end_ea))
        else:
            segment_name_count = get_segment_name_count()

            # add address range for each segment
            for segment_name in segments:
                segment = ida_segment.get_segm_by_name(segment_name)
                if segment is None or segment_name not in segment_name_count:
                    raise ValueError("Segment %s not found" % segment_name)
                if segment_name_count[segment_name] > 1:
                    raise ValueError("Segment name %s is not unique, specify an address range instead" % segment_name)
                final_ranges.append((segment.start_ea, segment.end_ea))

    if FUNCTIONS in kwargs and kwargs[FUNCTIONS] is not None:
        function_names = kwargs[FUNCTIONS]

        if not hasattr(function_names, '__iter__'):
            # lazy user didn't wrap a single function name in an iterable
            function_names = [function_names]

        if len(function_names) == 0:
            # all functions
            for function_start in idautils.Functions():
                function_start_list.append(function_start)
        else:
            for function_name in function_names:
                function_start = ida_name.get_name_ea(0, function_name)
                if function_start == idaapi.BADADDR:
                    raise ValueError("Function %s not found" % function_name)
                function_start_list.append(function_start)

    return normalize_ranges(final_ranges, function_start_list)


def get_address_iterator(filter_in=None, **kwargs):
    return address_range_iterator(parse_address_ranges(**kwargs),
                                  filter_in)


def user_names_only_filter_in(function_start):
    flags = ida_bytes.get_flags(function_start)
    return (ida_bytes.has_user_name(flags) and
            not ida_bytes.has_auto_name(flags))


def get_function_iterator(filter_in=None, **kwargs):
    return function_iterator(parse_address_ranges(**kwargs), filter_in)
