import idaapi
import string
from idc import *

# Rough outline of heuristic to find table of tasks started by OS init routine:
# 1) find string "tic:1" in memory
# 2) if it occurs in more than one address (e.g. iPhone4 basebands) use higher
#    address.
# 3) find references to "tic:1" string (in same segment)
# 4) apply taskdef_t struct to this memory location
# 5) if dword right before taskdef_t struct is small number (< 0x100),
#    go back one dword
# 6) go back -sizeof(taskdef_t) bytes in memory
# 7) check whether name_ptr points to something resembling an ASCII string
#    but not containing "HISR" as a substring.
#    [XXX: HISRs are not filtered yet, HISR creation routine uses slightly
#          different structure!]
# 8) if so, apply taskdef_t again
# 9) go forward with same strategy

def make_taskdef_t():
    id = idc.AddStrucEx(-1, "taskdef_t", 0)
    if id == -1:
	idc.Message("Error defining struct taskdef_t")
	return -1
    idc.AddStrucMember(id, "name_ptr",   -1, idc.FF_DWRD | idc.FF_DATA | idc.FF_0OFF, -1, 4)
    idc.AddStrucMember(id, "task_entry", -1, idc.FF_DWRD | idc.FF_DATA | idc.FF_0OFF, -1, 4)
    idc.AddStrucMember(id, "task_ptr",   -1, idc.FF_DWRD | idc.FF_0OFF | idc.FF_DATA, -1, 4)
    idc.AddStrucMember(id, "stack_addr", -1, idc.FF_DWRD | idc.FF_0OFF | idc.FF_DATA, -1, 4)
    idc.AddStrucMember(id, "stack_size", -1, idc.FF_DWRD | idc.FF_DATA              , -1, 4)
    idc.AddStrucMember(id, "priority",   -1, idc.FF_DWRD | idc.FF_DATA              , -1, 4)
    idc.AddStrucMember(id, "timeslice",  -1, idc.FF_DWRD | idc.FF_DATA              , -1, 4)
    idc.AddStrucMember(id, "argv",       -1, idc.FF_DWRD | idc.FF_DATA              , -1, 4)
    idc.AddStrucMember(id, "unknown1",   -1, idc.FF_DWRD | idc.FF_0OFF | idc.FF_DATA, -1, 4)

def make_task_definition(ea):
    if ea == BADADDR:
        print "invalid address. ignoring."
        return
    print "taskdef_t found at 0x%08x" % ea
    MakeStructEx(ea, -1, "taskdef_t")
    MakeStr(Dword(ea), BADADDR)
    task_basename = string.split(GetString(Dword(ea)), ":")[0]
    task_name     = "task_" + task_basename + "_entry"
    task_tcb_name = GetString(Dword(ea))
    task_tcb_name.replace(":", "_")
    task_tcb_name = "tcb_" + task_tcb_name
    task_entry = Dword(ea + 4)
    print "ref = 0x%08x -> %s (0x%08x)" % (ea, task_name, task_entry)
    if (task_entry & 1) == 1:
        # Thumb mode
	task_entry -= 1
        SetReg(task_entry, "T", 1);
        SetReg(task_entry+1, "T", 1);

    MakeCode(task_entry)
    MakeFunction(task_entry, BADADDR)
    MakeNameEx(task_entry, task_name, SN_CHECK)
    MakeNameEx(Dword(ea+8), task_tcb_name, SN_CHECK)

def build_tasktable():
    task_searched = "tic:1"
    searchstr = ''.join(["%02X " % ord(x) for x in task_searched])
    print searchstr
    addr = FindBinary(0, SEARCH_DOWN, searchstr)
    if addr == BADADDR:
        return
    print "string \"" + task_searched + "\" found at 0x%08x." % addr
    # and here we go again... for iPhone4 baseband firmwares
    addr2 = FindBinary(addr, SEARCH_DOWN|SEARCH_NEXT, searchstr)
    if addr2 != BADADDR:
        addr = addr2
        print "string \"" + task_searched + "\" also found at 0x%08x. using 2nd find." % addr
    task_name_ref = FindBinary(SegStart(addr), SEARCH_DOWN, "%08x" % addr, 16)
    if task_name_ref == BADADDR:
        return
    make_task_definition(task_name_ref)
    taskdef_t_id =  GetStrucIdByName("taskdef_t")
    if taskdef_t_id == -1:
        return
    addr = task_name_ref
    MakeStructEx(addr, -1, "taskdef_t")
    taskdef_t_size = GetStrucSize(taskdef_t_id)
    num_tasks = 1
    saved_addr = addr
    addr -= taskdef_t_size
    while Dword(addr) > 0x100:
        # check whether the address pointed to lives in the same segment
        if SegStart(Dword(addr)) != SegStart(addr):
            break
        make_task_definition(addr)        
        addr -= taskdef_t_size
	num_tasks += 1
    addr = saved_addr + taskdef_t_size
    while Dword(addr) > 0x100:
        if SegStart(Dword(addr)) != SegStart(addr):
            break
        make_task_definition(addr)        
        addr += taskdef_t_size
	num_tasks +=1
    print "%d tasks found." % num_tasks
    if Dword(addr) != num_tasks:
	print "no second table of tasks expected."
	return
    else:
	MakeDword(addr)
    print "looking for additional tasks..."
    num_tasks = 0
    addr += 4
    while Dword(addr) > 0x100:
        if SegStart(Dword(addr)) != SegStart(addr):
            break        
        make_task_definition(addr)        
        addr += taskdef_t_size
	num_tasks +=1
    print "another %d tasks found." % num_tasks

################################################################################

taskdef_t_id =  GetStrucIdByName("taskdef_t")
if taskdef_t_id != -1:
    DelStruc(taskdef_t_id)
    
make_taskdef_t()
build_tasktable()
