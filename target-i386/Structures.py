import functools
import struct
from Helpers import *

class Backend( object):

    def __init__( self):
        raise Exception( "The 'Backend' class is only an example interface. Subclass it and implement all the methods!")

    # Read length bytes at offset
    def read( self, offset, length):
        raise Exception( "The 'Backend' class is only an example interface. Subclass it and implement all the methods!")

    # Replace len( replacement) bytes at offset
    def write( self, offset, replacement):
        raise Exception( "The 'Backend' class is only an example interface. Subclass it and implement all the methods!")

class CopyingStringBackend( Backend):

    def __init__( self, buf, base = 0):
        self.buf = buf
        self.base = base

    def read( self, offset, length):
        if offset > len( self.buf) or offset + length > len( self.buf):
            raise IndexError( "string index %u+%u out of range, length of backend string is %u" % (offset, length, len( self.buf)))
        return self.buf[ self.base + offset: self.base + offset + length]

    def write( self, offset, replacement):
        try:
            self.buf[ self.base + offset: self.base + offset + len( replacement)] = replacement
        except TypeError:
            self.buf = self.buf[ : self.base + offset] \
                         + replacement \
                         + self.buf[ self.base + offset + len( replacement): ]

    def raw( self):
        return self.buf

    def __str__( self):
        return self.buf

    def __len__( self):
        return len( self.buf)

    def append( self, buf):
        self.buf = self.buf + buf

    def prepend( self, buf):
        self.buf = buf + self.buf


class ObjectBackend( Backend):

    def __init__( self, obj, base = 0, membername = "buf"):
        # need an object with a string member variable, its name defaulting to "buf"
        self.obj = obj
        self.membername = membername
        self.base = base

    def read( self, offset, length):
        buf = getattr( self.obj, self.membername)
        if offset > len( buf) or offset + length > len( buf):
            raise IndexError( "string index out of range")
        return buf[ self.base + offset: self.base + offset + length]

    def write( self, offset, replacement):
        try:
            getattr( self.obj, self.membername)[ self.base + offset: self.base + offset + len( replacement)] = replacement
        except TypeError:
            buf = getattr( self.obj, self.membername)
            setattr( self.obj, 
                     self.membername, 
                     buf[ : self.base + offset]  + replacement  + buf[ self.base + offset + len( replacement): ]
                   )
    def raw( self):
        return getattr( self.obj, self.membername)

    def __str__( self):
        return getattr( self.obj, self.membername)


    def __len__( self):
        return len( getattr( self.obj, self.membername))

    def append( self, buf):
        orig = getattr( self.obj, self.membername)
        setattr( self.obj, self.membername, orig + buf)

    def prepend( self, buf):
        orig = getattr( self.obj, self.membername)
        setattr( self.obj, self.membername, buf + orig)

class VMemBackend( Backend):
    # FIXME passing length to accomodate for a useful PE backend might not be the most elegant solution
    # FIXME that maximum limit is not all that nice either
    def __init__( self, base = 0, limit = 0x100000000):
        self.base = base
        self.limit = limit

    def read( self, offset, length):
        return PyFlxInstrument.vmem_read( self.base + offset, length)

    def write( self, offset, replacement):
        raise Exception( "write() not implemented in Virtual Memory Backend")

    def __len__( self):
        return self.limit - self.base


class Pointer( object):

    def __init__( self, backend, offset):
        self.backend = backend
        self.offset = offset
        s = ""
        self.pointer = None
        self.data = None
        s= self.backend.read( self.offset, 4)
        self.pointer = struct.unpack( "<I", s)[ 0]
        self.data = None
        # initializing the data structure here causes much grief, so don't do it


    def __len__(self):
        return 4

    def deref( self):
        try:
            s = self.backend.read( self.offset, 4)
        except:
            raise Exception( "Could not dereference a pointer of 0x%08x" % self.offset)
        p = struct.unpack( "<I",  s) [0]
        if self.ignore_null and 0 == p: # FIXME update pointer?
            return None
        if self.pointer != p:
            # NB: seems to flip-flop a lot.
            # Likely cause: flip-flops for the CurrentThread pointer only, which makes sense!
            self.pointer = p
            self.data = self.datatype( self.backend, self.pointer)
        if self.data == None:
            self.data = self.datatype( self.backend, self.pointer)
        return self.data

    def __str__( self):
        return "%s" % self.deref()

    def is_null( self):
        try:
            s = self.backend.read( self.offset, 4)
        except:
            raise Exception( "Could not dereference a pointer of 0x%08x" % self.offset)
        p = struct.unpack( "<I",  s) [0]
        return p == 0
 

def P( sometype, ignore_null = False):
    if ignore_null:
        return type( "I" + sometype.__class__.__name__, ( Pointer,), { "datatype": sometype, "ignore_null": True})
    else:
        return type( "I" + sometype.__class__.__name__, ( Pointer,), { "datatype": sometype, "ignore_null": False})


class StructuredData( object):
    """ Helper class providing a standard mechanism
        to work with structured data accessible through a
        backend object poviding read() and possibly write() """

#    attributes = []

    def get( dummy, name, self):
        (format, struct_offset, size) = self.attribute_dict[ name]
        offset = self.offset + struct_offset        
        retval = struct.unpack( "<" + format, self.backend.read( offset, size))
        if len( retval) == 1:
            return retval[ 0]
        else:
            return retval

    def raw( self):
        return self.backend.read( self.offset, self.len)

    def set( dummy, name, self, value):
        (format, struct_offset, size) = self.attribute_dict[ name]
        offset = self.offset + struct_offset
        replacement = struct.pack( "<" + format, value)
        self.backend.write( offset, replacement)

    def all_zero( self):
        return self.raw().strip( "\0") == ""


    # FIXME work with backend + offset, or throw new backends around?
    # FIXME does this change the subclass every time it is being instantiated?
    def __init__( self, backend, offset):

        self.backend = backend
        self.offset = offset

        struct_offset = 0
        self.attribute_dict = {}

        for (name, format) in self.attributes:

            # if format is a string, assume that it is for struct.unpack
            if type( format) == str:
                size = struct.calcsize( format)
                getfunc = functools.partial( self.get, name)
                setfunc = functools.partial( self.set, name)

                setattr( self.__class__, name, property( getfunc, setfunc))
        # else, assume "format" is a class which we need to instantiate
            else:
                structure = format( self.backend, self.offset + struct_offset)
                setattr( self, name, structure)
                size = len( structure)

            self.attribute_dict[ name] = ( format, struct_offset, size)
            struct_offset += size

        self.len = struct_offset


    def __len__( self):
        if hasattr( self, "len"):
            return self.len
        else:
            length = 0
            for (name, format) in self.attributes:
                if str == type( format):
                    length += struct.calcsize( format)
                else:
                    length += len( format)

    def __str__( self):
        result = ""
        for attr in self.attributes:
#            try:
                result += "%s: %s\n" % ( attr[ 0], getattr( self, attr[ 0]))
#            except:
#                result += "%s: unknown\n" % attr[ 0]
        return result




def LIST( sometype, le_member):
    return type( "LIST_" + sometype.__class__.__name__, ( LIST_ENTRY,), { "datatype": sometype, "le_member": le_member})



class LIST_ENTRY( object):

    def __init__( self, backend, offset):
        self.backend = backend
        self.head = offset
        self.cur_offset = self.head

        # now calculate the offset of self.le_member within the struct by hand
        # this is not perfect and requires a StructuredReaderBackedData-like datatype
        self.le_offset = 0


        # define a local function to help calculating type sizes
        # there are issues with the len() implementation of StructuredReaderBackedData
        def calcsize( sometype):
            size = 0
            if str == type( sometype):
                size = struct.calcsize( sometype)
            elif hasattr( sometype, "attributes"):
                for (name, format) in sometype.attributes:
                    size += calcsize( format)
            else:
                size = len( sometype)
            return size


        for (name, format) in self.datatype.attributes:
            if name == self.le_member:
                break
            else:
                self.le_offset += calcsize( format)

    def reset( self):
        self.cur_offset = self.head
        pass

    def next( self):
        # return the next structure in the list
        try:
            s = self.backend.read( self.cur_offset, 8)
        except:
            return None
        Flink, Blink = struct.unpack( "<II", s)
        self.cur_offset = Flink
        return self.cur()

    def prev( self):
        # return the previous structure in the list
        s = self.backend.read( self.cur_offset, 8, self.pdb)
        Flink, Blink = struct.unpack( "<II", s)
        self.cur_offset = Blink
        return self.cur()

    def cur( self):
        if self.cur_offset == self.head:
            return None

        # return the current structure in the list
        return self.datatype( self.backend, self.cur_offset - self.le_offset)

    def __len__( self):
        return 8


class UNICODE_STRING( StructuredData):
    attributes = [ ("Length", "H"),
                   ("MaximumLength", "H"),
                   ("Buffer", "I")] # PWSTR

    def str( self):
        # According to Microsoft, Length is in bytes, not characters
        s = self.backend.read( self.Buffer, self.Length)
        return s.decode( "UTF-16LE")

    def __str__( self):
        return self.str()

# Needed because python cannot handle recursive definitions using the P() function or class attributes
class PSEGMENT( Pointer):
    def __init__( self, backend, offset):
        self.datatype = SEGMENT
        self.ignore_null = False
        Pointer.__init__( self, backend, offset)

class PCONTROL_AREA( Pointer):
    def __init__( self, backend, offset):
        self.datatype = CONTROL_AREA
        self.ignore_null = False
        Pointer.__init__( self, backend, offset)

class PFILE_OBJECT( Pointer):
    def __init__( self, backend, offset):
        self.datatype = FILE_OBJECT
        self.ignore_null = False
        Pointer.__init__( self, backend, offset)

class PMMVAD( Pointer):
    def __init__( self, backend, offset):
        self.datatype = MMVAD
        self.ignore_null = False
        Pointer.__init__( self, backend, offset)

class FILE_OBJECT( StructuredData):
    attributes = [ ( "Type", "H"),
                   ( "Size", "H"),
                   ( "DeviceObject", "I"), # Ptr32 _DEVICE_OBJECT
                   ( "Vpb", "I"),          # Ptr32 _VPB
                   ( "FsContext", "I"),    # Ptr32 Void
                   ( "FsContext2", "I"),   # Ptr32 Void
                   ( "SectionObjectPointer", "I"), # Ptr32 _SECTION_OBJECT_POINTERS
                   ( "PrivateCacheMap", "I"), # Ptr32 Void
                   ( "FinalStatus", "i"),
                   ( "RelatedFileObject", PFILE_OBJECT),
                   ( "LockOperation", "B"),
                   ( "DeletePending", "B"),
                   ( "ReadAccess", "B"),
                   ( "WriteAccess", "B"),
                   ( "DeleteAccess", "B"),
                   ( "SharedRead", "B"),
                   ( "SharedWrite", "B"),
                   ( "SharedDelete", "B"),
                   ( "Flags", "I"),
                   ( "FileName", UNICODE_STRING),
                   ( "CurrentByteOffset", "Q"),
                   ( "Waiters", "I"),
                   ( "Busy", "I"),
                   ( "LastLock", "I"),          # Ptr32 Void
                   ( "Lock", "16s"),            # _KEVENT
                   ( "Event", "16s"),           # _KEVENT
                   ( "CompletionContext", "I"), # : Ptr32 _IO_COMPLETION_CONTEXT
                 ]

class CONTROL_AREA( StructuredData):
    attributes = [ ( "Segment", PSEGMENT),
                   ( "DereferenceList", "II"), #_LIST_ENTRY
                   ( "NumberOfSectionReferences", "I"),
                   ( "NumberOfPfnReferences", "I"),
                   ( "NumberOfMappedViews", "I"),
                   ( "NumberOfSubsections", "H"),
                   ( "FlushInProgressCount", "H"),
                   ( "NumberOfUserReferences", "I"),
                   ( "u", "I"),
                   ( "FilePointer", PFILE_OBJECT),
                   ( "WaitingForDeletion", "I"), # Ptr32 _EVENT_COUNTER
                   ( "ModifiedWriteCount", "H"),
                   ( "NumberOfSystemCacheViews", "H")
                 ]

class SEGMENT( StructuredData):
    attributes = [ ( "ControlArea", PCONTROL_AREA),
                   ( "TotalNumberOfPtes", "I"),
                   ( "NonExtendedPtes", "I"),
                   ( "WritableUserReferences", "I"),
                   ( "SizeOfSegment", "Q"),
                   ( "SegmentPteTemplate", "Q"), # MMPTE
                   ( "NumberOfCommittedPages", "I"),
                   ( "ExtendInfo", "I"),         # Ptr32 _MMEXTEND_INFO
                   ( "SystemImageBase", "I"),    # Ptr32 Void
                   ( "BasedAddress", "I"),       # Ptr32 Void
                   ( "u1", "I"),                 # __unnamed
                   ( "u2", "I"),                 # __unnamed
# not really need anyway
#                   ( "PrototypePte", "I4x"),     # Ptr32 _MMPTE + 4 byte padding?
#                   ( "ThePtes", "Q")             # [1] _MMPTE
                 ]


class MMVAD( StructuredData):
    attributes = [ ( "StartingVpn", "I"),
                   ( "EndingVpn", "I"),
                   ( "Parent", PMMVAD),
                   ( "LeftChild", PMMVAD),
                   ( "RightChild", PMMVAD),
                   ( "u", "I"),
                   # ^ MMVAD_SHORT
                   # v MMVAD
                   ( "ControlArea", P( CONTROL_AREA, True)), # can that be NULL?
                   ( "FirstPrototypePte", "I"), # Ptr32 _MMPTE
                   ( "LastContiguousPte", "I"), # Ptr32 _MMPTE
                   ( "u2", "I")
                 ]



class LDR_DATA_TABLE_ENTRY( StructuredData):
    attributes = [ ("InLoadOrderLinks", "2I"), # LIST_ENTRY InLoadOrderLinks // +0x000
                   ("InMemoryOrderLinks", "2I"), # LIST_ENTRY InMemoryOrderLinks // +0x008
                   ("InInitializationOrderLinks", "2I"), # LIST_ENTRY InInitializationOrderLinks // +0x010
                   ("DllBase", "I"), # PVOID DllBase // +0x018
                   ("EntryPoint", "I"), # PVOID EntryPoint // +0x01c
                   ("SizeOfImage", "I"), # ULONG SizeOfImage // +0x020
                   ("FullDllName", UNICODE_STRING), # UNICODE_STRING FullDllName // +0x024
                   ("BaseDllName", UNICODE_STRING), # UNICODE_STRING BaseDllName // +0x02c
                   ("Flags", "I"), # ULONG Flags // +0x034
                   ("LoadCount", "H"), # USHORT LoadCount // +0x038
                   ("TlsIndex", "H"), # USHORT TlsIndex // +0x03a
                   #   union {
                   ("HashLinks", "2I"), # LIST_ENTRY HashLinks // +0x03c
                   #("SectionPointer", "I"), # PVOID SectionPointer // +0x03c
                   #   };
                   ("CheckSum", "I"), # ULONG CheckSum // +0x040
                   #   union {
                   ("TimeDateStamp", "I"), # ULONG TimeDateStamp // +0x044
                   #("LoadedImports", "I"), # PVOID LoadedImports // +0x044
                   #   };
                   ("EntryPointActivationContext", "I"), # PVOID EntryPointActivationContext // +0x048
                   ("PatchInformation", "I")] # PVOID PatchInformation // +0x04c

class PEB_LDR_DATA( StructuredData):
    attributes = [ ("Length", "I"), # ULONG Length // +0x000
                   ("Initialized", "Bxxx"), # UCHAR Initialized // +0x004
                   ("SsHandle", "I"), # PVOID SsHandle // +0x008
                   ("InLoadOrderModuleList", "2I"), # LIST_ENTRY InLoadOrderModuleList // +0x00c
                   ("InMemoryOrderModuleList", LIST( LDR_DATA_TABLE_ENTRY, "InMemoryOrderLinks")), # LIST_ENTRY InMemoryOrderModuleList // +0x014
                   ("InInitializationOrderModuleList", "2I"), # LIST_ENTRY InInitializationOrderModuleList // +0x01c
                   ("EntryInProgress", "I")] # PVOID EntryInProgress // +0x024



class PEB( StructuredData):
    attributes = [ ("InheritedAddressSpace", "B"), # UCHAR InheritedAddressSpace // +0x000
                   ("ReadImageFileExecOptions", "B"), # UCHAR ReadImageFileExecOptions // +0x001
                   ("BeingDebugged", "B"), # UCHAR BeingDebugged // +0x002
                   ("SpareBool", "B"), # UCHAR SpareBool // +0x003
                   ("Mutant", "I"), # PVOID Mutant // +0x004
                   ("ImageBaseAddress", "I"), # PVOID ImageBaseAddress // +0x008
                   ("Ldr", P(PEB_LDR_DATA)), # PPEB_LDR_DATA Ldr // +0x00c
                   ("ProcessParameters", "I"), #"PRTL_USER_PROCESS_PARAMETERS"), # PRTL_USER_PROCESS_PARAMETERS ProcessParameters // +0x010
                   ("SubSystemData", "I"), # PVOID SubSystemData // +0x014
                   ("ProcessHeap", "I"), # PVOID ProcessHeap // +0x018
                   ("FastPebLock", "I"), #"PRTL_CRITICAL_SECTION"), # PRTL_CRITICAL_SECTION FastPebLock // +0x01c
                   ("FastPebLockRoutine", "I"), # PVOID FastPebLockRoutine // +0x020
                   ("FastPebUnlockRoutine", "I"), # PVOID FastPebUnlockRoutine // +0x024
                   ("EnvironmentUpdateCount", "I"), # ULONG EnvironmentUpdateCount // +0x028
                   ("KernelCallbackTable", "I"), # PVOID KernelCallbackTable // +0x02c
                   ("SystemReserved", "I"), # ULONG SystemReserved[1] // +0x030
                   ("AtlThunkSListPtr32", "I"), # ULONG AtlThunkSListPtr32 // +0x034
                   ("FreeList", "I"), #"PPEB_FREE_BLOCK"), # PPEB_FREE_BLOCK FreeList // +0x038
                   ("TlsExpansionCounter", "I"), # ULONG TlsExpansionCounter // +0x03c
                   ("TlsBitmap", "I"), # PVOID TlsBitmap // +0x040
                   ("TlsBitmapBits", "2I"), # ULONG TlsBitmapBits[2] // +0x044
                   ("ReadOnlySharedMemoryBase", "I"), # PVOID ReadOnlySharedMemoryBase // +0x04c
                   ("ReadOnlySharedMemoryHeap", "I"), # PVOID ReadOnlySharedMemoryHeap // +0x050
                   ("ReadOnlyStaticServerData", "I"), # PVOID *ReadOnlyStaticServerData // +0x054
                   ("AnsiCodePageData", "I"), # PVOID AnsiCodePageData // +0x058
                   ("OemCodePageData", "I"), # PVOID OemCodePageData // +0x05c
                   ("UnicodeCaseTableData", "I"), # PVOID UnicodeCaseTableData // +0x060
                   ("NumberOfProcessors", "I"), # ULONG NumberOfProcessors // +0x064
                   ("NtGlobalFlag", "I"), # ULONG NtGlobalFlag // +0x068
                   ("CriticalSectionTimeout", "q"), # _LARGE_INTEGER CriticalSectionTimeout // +0x070
                   ("HeapSegmentReserve", "I"), # ULONG HeapSegmentReserve // +0x078
                   ("HeapSegmentCommit", "I"), # ULONG HeapSegmentCommit // +0x07c
                   ("HeapDeCommitTotalFreeThreshold", "I"), # ULONG HeapDeCommitTotalFreeThreshold // +0x080
                   ("HeapDeCommitFreeBlockThreshold", "I"), # ULONG HeapDeCommitFreeBlockThreshold // +0x084
                   ("NumberOfHeaps", "I"), # ULONG NumberOfHeaps // +0x088
                   ("MaximumNumberOfHeaps", "I"), # ULONG MaximumNumberOfHeaps // +0x08c
                   ("*ProcessHeaps", "I"), # PVOID *ProcessHeaps // +0x090
                   ("GdiSharedHandleTable", "I"), # PVOID GdiSharedHandleTable // +0x094
                   ("ProcessStarterHelper", "I"), # PVOID ProcessStarterHelper // +0x098
                   ("GdiDCAttributeList", "I"), # ULONG GdiDCAttributeList // +0x09c
                   ("LoaderLock", "I"), # PVOID LoaderLock // +0x0a0
                   ("OSMajorVersion", "I"), # ULONG OSMajorVersion // +0x0a4
                   ("OSMinorVersion", "I"), # ULONG OSMinorVersion // +0x0a8
                   ("OSBuildNumber", "H"), # USHORT OSBuildNumber // +0x0ac
                   ("OSCSDVersion", "H"), # USHORT OSCSDVersion // +0x0ae
                   ("OSPlatformId", "I"), # ULONG OSPlatformId // +0x0b0
                   ("ImageSubsystem", "I"), # ULONG ImageSubsystem // +0x0b4
                   ("ImageSubsystemMajorVersion", "I"), # ULONG ImageSubsystemMajorVersion // +0x0b8
                   ("ImageSubsystemMinorVersion", "I"), # ULONG ImageSubsystemMinorVersion // +0x0bc
                   ("ImageProcessAffinityMask", "I"), # ULONG ImageProcessAffinityMask // +0x0c0
                   ("GdiHandleBuffer", "34I"), # ULONG GdiHandleBuffer[34] // +0x0c4
                   ("PostProcessInitRoutine", "I"), # PVOID PostProcessInitRoutine // +0x14c
                   ("TlsExpansionBitmap", "I"), # PVOID TlsExpansionBitmap // +0x150
                   ("TlsExpansionBitmapBits", "32I"), # ULONG TlsExpansionBitmapBits[32] // +0x154
                   ("SessionId", "I"), # ULONG SessionId // +0x1d4
                   ("AppCompatFlags", "Q"), # _ULARGE_INTEGER AppCompatFlags // +0x1d8
                   ("AppCompatFlagsUser", "Q"), # _ULARGE_INTEGER AppCompatFlagsUser // +0x1e0
                   ("pShimData", "I"), # PVOID pShimData // +0x1e8
                   ("AppCompatInfo", "I"), # PVOID AppCompatInfo // +0x1ec
                   ("CSDVersion", UNICODE_STRING), # _UNICODE_STRING CSDVersion // +0x1f0
                   ("ActivationContextData", "I"), # PVOID ActivationContextData // +0x1f8
                   ("ProcessAssemblyStorageMap", "I"), # PVOID ProcessAssemblyStorageMap // +0x1fc
                   ("SystemDefaultActivationContextData", "I"), # PVOID SystemDefaultActivationContextData // +0x200
                   ("SystemAssemblyStorageMap", "I"), # PVOID SystemAssemblyStorageMap // +0x204
                   ("MinimumStackCommit", "I")] # ULONG MinimumStackCommit // +0x208



class KPROCESS( StructuredData):
    attributes = [ ("Header", "16s"), # _DISPATCHER_HEADER Header // +0x000
                   ("ProfileListHead", "2I"), # _LIST_ENTRY ProfileListHead // +0x010
                   ("DirectoryTableBase", "2I"), # ULONG DirectoryTableBase[2] // +0x018
                   ("LdtDescriptor", "8s"), # _KGDTENTRY LdtDescriptor // +0x020
                   ("Int21Descriptor", "8s"), # _KIDTENTRY Int21Descriptor // +0x028
                   ("IopmOffset", "H"), # USHORT IopmOffset // +0x030
                   ("Iopl", "B"), # UCHAR Iopl // +0x032
                   ("Unused", "B"), # UCHAR Unused // +0x033
                   ("ActiveProcessors", "I"), # ULONG ActiveProcessors // +0x034
                   ("KernelTime", "I"), # ULONG KernelTime // +0x038
                   ("UserTime", "I"), # ULONG UserTime // +0x03c
                   ("ReadyListHead", "2I"), # _LIST_ENTRY ReadyListHead // +0x040
                   ("SwapListEntry", "I"), # _SINGLE_LIST_ENTRY SwapListEntry // +0x048
                   ("VdmTrapcHandler", "I"), # PVOID VdmTrapcHandler // +0x04c
                   ("ThreadListHead", "2I"), # _LIST_ENTRY ThreadListHead // +0x050
                   ("ProcessLock", "I"), # ULONG ProcessLock // +0x058
                   ("Affinity", "I"), # ULONG Affinity // +0x05c
                   ("StackCount", "H"), # USHORT StackCount // +0x060
                   ("BasePriority", "b"), # CHAR BasePriority // +0x062
                   ("ThreadQuantum", "b"), # CHAR ThreadQuantum // +0x063
                   ("AutoAlignment", "B"), # UCHAR AutoAlignment // +0x064
                   ("State", "B"), # UCHAR State // +0x065
                   ("ThreadSeed", "B"), # UCHAR ThreadSeed // +0x066
                   ("DisableBoost", "B"), # UCHAR DisableBoost // +0x067
                   ("PowerState", "B"), # UCHAR PowerState // +0x068
                   ("DisableQuantum", "B"), # UCHAR DisableQuantum // +0x069
                   ("IdealNode", "B"), # UCHAR IdealNode // +0x06a
                   #union {
                   #("Flags", "_KEXECUTE_OPTIONS"), # _KEXECUTE_OPTIONS Flags // +0x06b
                   ("ExecuteOptions", "B") # UCHAR ExecuteOptions // +0x06b
                 ]

class EPROCESS( StructuredData):
    attributes = [ ("Pcb", KPROCESS), # _KPROCESS Pcb // +0x000
                   ("ProcessLock", "I"), # _EX_PUSH_LOCK ProcessLock // +0x06c
                   ("CreateTime", "q"), # _LARGE_INTEGER CreateTime // +0x070
                   ("ExitTime", "q"), # _LARGE_INTEGER ExitTime // +0x078
                   ("RundownProtect", "I"), # _EX_RUNDOWN_REF RundownProtect // +0x080
                   ("UniqueProcessId", "I"), # PVOID UniqueProcessId // +0x084
                   ("ActiveProcessLinks", "2I"), # _LIST_ENTRY ActiveProcessLinks // +0x088
                   ("QuotaUsage", "3I"), # ULONG QuotaUsage[3] // +0x090
                   ("QuotaPeak", "3I"), # ULONG QuotaPeak[3] // +0x09c
                   ("CommitCHARge", "I"), # ULONG CommitCHARge // +0x0a8
                   ("PeakVirtualSize", "I"), # ULONG PeakVirtualSize // +0x0ac
                   ("VirtualSize", "I"), # ULONG VirtualSize // +0x0b0
                   ("SessionProcessLinks", "2I"), # _LIST_ENTRY SessionProcessLinks // +0x0b4
                   ("DebugPort", "I"), # PVOID DebugPort // +0x0bc
                   ("ExceptionPort", "I"), # PVOID ExceptionPort // +0x0c0
                   ("ObjectTable", "I"), # PHANDLE_TABLE ObjectTable // +0x0c4
                   ("Token", "I"), # _EX_FAST_REF Token // +0x0c8
                   ("WorkingSetLock", "32s"), # _FAST_MUTEX WorkingSetLock // +0x0cc
                   ("WorkingSetPage", "I"), # ULONG WorkingSetPage // +0x0ec
                   ("AddressCreationLock", "32s"), # _FAST_MUTEX AddressCreationLock // +0x0f0
                   ("HyperSpaceLock", "I"), # ULONG HyperSpaceLock // +0x110
                   ("ForkInProgress", "I"), # PETHREAD ForkInProgress // +0x114
                   ("HardwareTrigger", "I"), # ULONG HardwareTrigger // +0x118
                   ("VadRoot", P( MMVAD)), # PVOID VadRoot // +0x11c
                   ("VadHint", "I"), # PVOID VadHint // +0x120
                   ("CloneRoot", "I"), # PVOID CloneRoot // +0x124
                   ("NumberOfPrivatePages", "I"), # ULONG NumberOfPrivatePages // +0x128
                   ("NumberOfLockedPages", "I"), # ULONG NumberOfLockedPages // +0x12c
                   ("Win32Process", "I"), # PVOID Win32Process // +0x130
                   ("Job", "I"), # PEJOB Job // +0x134
                   ("SectionObject", "I"), # PVOID SectionObject // +0x138
                   ("SectionBaseAddress", "I"), # PVOID SectionBaseAddress // +0x13c
                   ("QuotaBlock", "I"), # PEPROCESS_QUOTA_BLOCK QuotaBlock // +0x140
                   ("WorkingSetWatch", "I"), # PPAGEFAULT_HISTORY WorkingSetWatch // +0x144
                   ("Win32WindowStation", "I"), # PVOID Win32WindowStation // +0x148
                   ("InheritedFromUniqueProcessId", "I"), # PVOID InheritedFromUniqueProcessId // +0x14c
                   ("LdtInformation", "I"), # PVOID LdtInformation // +0x150
                   ("VadFreeHint", "I"), # PVOID VadFreeHint // +0x154
                   ("VdmObjects", "I"), # PVOID VdmObjects // +0x158
                   ("DeviceMap", "I"), # PVOID DeviceMap // +0x15c
                   ("PhysicalVadList", "2I"), # LIST_ENTRY PhysicalVadList // +0x160
                   #union {
                   #("PageDirectoryPte", "_HARDWARE_PTE_X86"), # _HARDWARE_PTE_X86 PageDirectoryPte // +0x168
                   ("Filler", "Q"), # ULONGLONG Filler // +0x168
                   #};
                   ("Session", "I"), # PVOID Session // +0x170
                   ("ImageFileName", "16s"), # UCHAR ImageFileName[16] // +0x174
                   ("JobLinks", "2I"), # LIST_ENTRY JobLinks // +0x184
                   ("LockedPagesList", "I"), # PVOID LockedPagesList // +0x18c
                   ("ThreadListHead", "2I"), # LIST_ENTRY ThreadListHead // +0x190
                   ("SecurityPort", "I"), # PVOID SecurityPort // +0x198
                   ("PaeTop", "I"), # PVOID PaeTop // +0x19c
                   ("ActiveThreads", "I"), # ULONG ActiveThreads // +0x1a0
                   ("GrantedAccess", "I"), # ULONG GrantedAccess // +0x1a4
                   ("DefaultHardErrorProcessing", "I"), # ULONG DefaultHardErrorProcessing // +0x1a8
                   ("LastThreadExitStatus", "i"), # LONG LastThreadExitStatus // +0x1ac
                   ("Peb", P(PEB)), # PPEB Peb // +0x1b0
                   ("PrefetchTrace", "I"), # _EX_FAST_REF PrefetchTrace // +0x1b4
                   ("ReadOperationCount", "q"), # _LARGE_INTEGER ReadOperationCount // +0x1b8
                   ("WriteOperationCount", "q"), # _LARGE_INTEGER WriteOperationCount // +0x1c0
                   ("OtherOperationCount", "q"), # _LARGE_INTEGER OtherOperationCount // +0x1c8
                   ("ReadTransferCount", "q"), # _LARGE_INTEGER ReadTransferCount // +0x1d0
                   ("WriteTransferCount", "q"), # _LARGE_INTEGER WriteTransferCount // +0x1d8
                   ("OtherTransferCount", "q"), # _LARGE_INTEGER OtherTransferCount // +0x1e0
                   ("CommitCHARgeLimit", "I"), # ULONG CommitCHARgeLimit // +0x1e8
                   ("CommitCHARgePeak", "I"), # ULONG CommitCHARgePeak // +0x1ec
                   ("AweInfo", "I"), # PVOID AweInfo // +0x1f0
                   ("SeAuditProcessCreationInfo", "I"), # _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo // +0x1f4
                   ("Vm", "64s"), # _MMSUPPORT Vm // +0x1f8
                   ("LastFaultCount", "I"), # ULONG LastFaultCount // +0x238
                   ("ModifiedPageCount", "I"), # ULONG ModifiedPageCount // +0x23c
                   ("NumberOfVads", "I"), # ULONG NumberOfVads // +0x240
                   ("JobStatus", "I"), # ULONG JobStatus // +0x244
                   #union {
                   #   struct {
                   #("CreateReported:1", "I"), # ULONG CreateReported:1 // +0x248
                   #("NoDebugInherit:1", "I"), # ULONG NoDebugInherit:1 // +0x248
                   #("ProcessExiting:1", "I"), # ULONG ProcessExiting:1 // +0x248
                   #("ProcessDelete:1", "I"), # ULONG ProcessDelete:1 // +0x248
                   #("Wow64SplitPages:1", "I"), # ULONG Wow64SplitPages:1 // +0x248
                   #("VmDeleted:1", "I"), # ULONG VmDeleted:1 // +0x248
                   #("OutswapEnabled:1", "I"), # ULONG OutswapEnabled:1 // +0x248
                   #("Outswapped:1", "I"), # ULONG Outswapped:1 // +0x248
                   #("ForkFailed:1", "I"), # ULONG ForkFailed:1 // +0x248
                   #("HasPhysicalVad:1", "I"), # ULONG HasPhysicalVad:1 // +0x248
                   #("AddressSpaceInitialized:2", "I"), # ULONG AddressSpaceInitialized:2 // +0x248
                   #("SetTimerResolution:1", "I"), # ULONG SetTimerResolution:1 // +0x248
                   #("BreakOnTermination:1", "I"), # ULONG BreakOnTermination:1 // +0x248
                   #("SessionCreationUnderway:1", "I"), # ULONG SessionCreationUnderway:1 // +0x248
                   #("WriteWatch:1", "I"), # ULONG WriteWatch:1 // +0x248
                   #("ProcessInSession:1", "I"), # ULONG ProcessInSession:1 // +0x248
                   #("OverrideAddressSpace:1", "I"), # ULONG OverrideAddressSpace:1 // +0x248
                   #("HasAddressSpace:1", "I"), # ULONG HasAddressSpace:1 // +0x248
                   #("LaunchPrefetched:1", "I"), # ULONG LaunchPrefetched:1 // +0x248
                   #("InjectInpageErrors:1", "I"), # ULONG InjectInpageErrors:1 // +0x248
                   #("VmTopDown:1", "I"), # ULONG VmTopDown:1 // +0x248
                   #("Unused3:1", "I"), # ULONG Unused3:1 // +0x248
                   #("Unused4:1", "I"), # ULONG Unused4:1 // +0x248
                   #("VdmAllowed:1", "I"), # ULONG VdmAllowed:1 // +0x248
                   #("Unused:5", "I"), # ULONG Unused:5 // +0x248
                   #("Unused1:1", "I"), # ULONG Unused1:1 // +0x248
                   #("Unused2:1", "I"), # ULONG Unused2:1 // +0x248
                   #   };
                   ( "Flags", "I"), #   ULONG Flags;
                   #};
                   ("ExitStatus", "i"), # LONG ExitStatus // +0x24c
                   ("NextPageColor", "H"), # USHORT NextPageColor // +0x250
                   ("SubSystemMinorVersion", "B"), # UCHAR SubSystemMinorVersion // +0x252
                   ("SubSystemMajorVersion", "B"), # UCHAR SubSystemMajorVersion // +0x253
                   ("SubSystemVersion", "H"), # USHORT SubSystemVersion // +0x252
                   ("PriorityClass", "B"), # UCHAR PriorityClass // +0x254
                   ("WorkingSetAcquiredUnsafe", "B"), # UCHAR WorkingSetAcquiredUnsafe // +0x255
                   ("Cookie", "I") # ULONG Cookie // +0x258
                   ]


class KAPC_STATE( StructuredData):
    attributes = [
                   ("ApcListHead", "4I"), # _LIST_ENTRY ApcListHead[2] // +0x000
                   ("Process", P(EPROCESS)), # FIXME PKPROCESS Process // +0x010
                   ("KernelApcInProgress", "B"), # UCHAR KernelApcInProgress // +0x014
                   ("KernelApcPending", "B"), # UCHAR KernelApcPending // +0x015
                   ("UserApcPending", "B"), # UCHAR UserApcPending // +0x016
                   ("Pad", "B")
                 ]

class CLIENT_ID( StructuredData):
    attributes = [
                     ("UniqueProcess", "I"),
                     ("UniqueThread", "I")
                 ]

class TEB( StructuredData):
    attributes = [ ("NtTib", "28c"), # _NT_TIB NtTib // +0x000
                   ("EnvironmentPointer", "I"), # Ptr32 Void EnvironmentPointer // +0x01c
                   ("ClientId", CLIENT_ID), # _CLIENT_ID ClientId // +0x020
                   ("ActiveRpcHandle", "I"), # Ptr32 Void ActiveRpcHandle // +0x028
                   ("ThreadLocalStoragePointer", "I"), # Ptr32 Void ThreadLocalStoragePointer // +0x02c
                   ("ProcessEnvironmentBlock", "I"), # Ptr32 _PEB ProcessEnvironmentBlock // +0x030
                   ("LastErrorValue", "I"), # Uint4B LastErrorValue // +0x034
                   ("CountOfOwnedCriticalSections", "I"), # Uint4B CountOfOwnedCriticalSections // +0x038
                   ("CsrClientThread", "I"), # Ptr32 CsrClientThread // +0x03c
                   ("Win32ThreadInfo", "I"), # Ptr32 Void Win32ThreadInfo // +0x040
                   ("User32Reserved", "26I"), # Uint4B User32Reserved[26] // +0x044
                   ("UserReserved", "5I"), # Uint4B UserReserved[5] // +0x0ac
                   ("WOW32Reserved", "I"), # Ptr32 Void WOW32Reserved // +0x0c0
                   ("CurrentLocale", "I"), # Uint4B CurrentLocale // +0x0c4
                   ("FpSoftwareStatusRegister", "I"), # Uint4B FpSoftwareStatusRegister // +0x0c8
                   ("SystemReserved1", "54I"), # Ptr32 Void SystemReserved1[54] // +0x0cc
                   ("ExceptionCode", "i"), # Int4B ExceptionCode // +0x1a4
                   ("ActivationContextStack", "20c"), # _ACTIVATION_CONTEXT_STACK ActivationContextStack // +0x1a8
                   ("SpareBytes1", "24B"), # UChar SpareBytes1[24] // +0x1bc
                   ("GdiTebBatch", "1248c"), # _GDI_TEB_BATCH GdiTebBatch // +0x1d4
                   ("RealClientId", "8c"), # _CLIENT_ID RealClientId // +0x6b4
                   ("GdiCachedProcessHandle", "I"), # Ptr32 Void GdiCachedProcessHandle // +0x6bc
                   ("GdiClientPID", "I"), # Uint4B GdiClientPID // +0x6c0
                   ("GdiClientTID", "I"), # Uint4B GdiClientTID // +0x6c4
                   ("GdiThreadLocalInfo", "I"), # Ptr32 Void GdiThreadLocalInfo // +0x6c8
                   ("Win32ClientInfo", "62I"), # Uint4B Win32ClientInfo[62] // +0x6cc
                   ("glDispatchTable", "233I"), # Ptr32 Void glDispatchTable[233] // +0x7c4
                   ("glReserved1", "29I"), # Uint4B glReserved1[29] // +0xb68
                   ("glReserved2", "I"), # Ptr32 Void glReserved2 // +0xbdc
                   ("glSectionInfo", "I"), # Ptr32 Void glSectionInfo // +0xbe0
                   ("glSection", "I"), # Ptr32 Void glSection // +0xbe4
                   ("glTable", "I"), # Ptr32 Void glTable // +0xbe8
                   ("glCurrentRC", "I"), # Ptr32 Void glCurrentRC // +0xbec
                   ("glContext", "I"), # Ptr32 Void glContext // +0xbf0
                   ("LastStatusValue", "I"), # Uint4B LastStatusValue // +0xbf4
                   ("StaticUnicodeString", UNICODE_STRING), # _UNICODE_STRING StaticUnicodeString // +0xbf8
                   ("StaticUnicodeBuffer", "261H2x"), # Uint2B StaticUnicodeBuffer[261] // +0xc00
                   ("DeallocationStack", "I"), # Ptr32 Void DeallocationStack // +0xe0c
                   ("TlsSlots", "64I"), # Ptr32 Void TlsSlots[64] // +0xe10
                   ("TlsLinks", "2I"), # _LIST_ENTRY TlsLinks // +0xf10
                   ("Vdm", "I"), # Ptr32 Void Vdm // +0xf18
                   ("ReservedForNtRpc", "I"), # Ptr32 Void ReservedForNtRpc // +0xf1c
                   ("DbgSsReserved", "2I"), # Ptr32 Void DbgSsReserved[2] // +0xf20
                   ("HardErrorsAreDisabled", "I"), # Uint4B HardErrorsAreDisabled // +0xf28
                   ("Instrumentation", "16I"), # Ptr32 Void Instrumentation[16] // +0xf2c
                   ("WinSockData", "I"), # Ptr32 Void WinSockData // +0xf6c
                   ("GdiBatchCount", "I"), # Uint4B GdiBatchCount // +0xf70
                   ("InDbgPrint", "B"), # UChar InDbgPrint // +0xf74
                   ("FreeStackOnTermination", "B"), # UChar FreeStackOnTermination // +0xf75
                   ("HasFiberData", "B"), # UChar HasFiberData // +0xf76
                   ("IdealProcessor", "B"), # UChar IdealProcessor // +0xf77
                   ("Spare3", "I"), # Uint4B Spare3 // +0xf78
                   ("ReservedForPerf", "I"), # Ptr32 Void ReservedForPerf // +0xf7c
                   ("ReservedForOle", "I"), # Ptr32 Void ReservedForOle // +0xf80
                   ("WaitingOnLoaderLock", "I"), # Uint4B WaitingOnLoaderLock // +0xf84
                   ("Wx86Thread", "12c"), # _Wx86ThreadState Wx86Thread // +0xf88
                   ("TlsExpansionSlots", "I"), # Ptr32 Ptr32 Void TlsExpansionSlots // +0xf94
                   ("ImpersonationLocale", "I"), # Uint4B ImpersonationLocale // +0xf98
                   ("IsImpersonating", "I"), # Uint4B IsImpersonating // +0xf9c
                   ("NlsCache", "I"), # Ptr32 Void NlsCache // +0xfa0
                   ("pShimData", "I"), # Ptr32 Void pShimData // +0xfa4
                   ("HeapVirtualAffinity", "I"), # Uint4B HeapVirtualAffinity // +0xfa8
                   ("CurrentTransactionHandle", "I"), # Ptr32 Void CurrentTransactionHandle // +0xfac
                   ("_TEB_ACTIVE_FRAME ActiveFrame", "I"), # Ptr32 _TEB_ACTIVE_FRAME ActiveFrame // +0xfb0
                   ("SafeThunkCall", "B"), # UChar SafeThunkCall // +0xfb4
                   ("BooleanSpare", "3B"), # UChar BooleanSpare[3] // +0xfb5
                 ]

# !!! only works for 2600 <= build < 3790
class KTHREAD( StructuredData):
    attributes = [ ("Header", "16s"), # DISPATCHER_HEADER Header // +0x000
                   ("MutantListHead", "2I"), # LIST_ENTRY MutantListHead // +0x010
                   ("InitialStack", "I"), # PVOID InitialStack // +0x018
                   ("StackLimit", "I"), # PVOID StackLimit // +0x01c
                   ("Teb", P(TEB)), # PVOID Teb // +0x020
                   ("TlsArray", "I"), # PVOID TlsArray // +0x024
                   ("KernelStack", "I"), # PVOID KernelStack // +0x028
                   ("DebugActive", "B"), # UCHAR DebugActive // +0x02c
                   ("State", "B"), # UCHAR State // +0x02d
                   ("Alerted", "2s"), # UCHAR Alerted[2] // +0x02e
                   ("Iopl", "B"), # UCHAR Iopl // +0x030
                   ("NpxState", "B"), # UCHAR NpxState // +0x031
                   ("Saturation", "b"), # CHAR Saturation // +0x032
                   ("Priority", "b"), # CHAR Priority // +0x033
                   ("ApcState", KAPC_STATE), # KAPC_STATE ApcState // +0x034
                   ("ContextSwitches", "I"), # ULONG ContextSwitches // +0x04c
                   ("IdleSwapBlock", "B"), # UCHAR IdleSwapBlock // +0x050
                   ("Spare0", "3s"), # UCHAR Spare0[3] // +0x051
                   ("WaitStatus", "i"), # LONG WaitStatus // +0x054
                   ("WaitIrql", "B"), # UCHAR WaitIrql // +0x058
                   ("WaitMode", "b"), # CHAR WaitMode // +0x059
                   ("WaitNext", "B"), # UCHAR WaitNext // +0x05a
                   ("WaitReason", "B"), # UCHAR WaitReason // +0x05b
                   ("WaitBlockList", "I"), # PKWAIT_BLOCK WaitBlockList // +0x05c
                   #   union {
                   ("WaitListEntry", "2I"), # LIST_ENTRY WaitListEntry // +0x060
                   #("SwapListEntry", "SINGLE_LIST_ENTRY"), # SINGLE_LIST_ENTRY SwapListEntry // +0x060
                   #   };
                   ("WaitTime", "I"), # ULONG WaitTime // +0x068
                   ("BasePriority", "b"), # CHAR BasePriority // +0x06c
                   ("DecrementCount", "B"), # UCHAR DecrementCount // +0x06d
                   ("PriorityDecrement", "b"), # CHAR PriorityDecrement // +0x06e
                   ("Quantum", "b"), # CHAR Quantum // +0x06f
                   ("WaitBlock", "96s"), # KWAIT_BLOCK WaitBlock[4] // +0x070
                   ("LegoData", "I"), # PVOID LegoData // +0x0d0
                   ("KernelApcDisable", "I"), # ULONG KernelApcDisable // +0x0d4
                   ("UserAffinity", "I"), # ULONG UserAffinity // +0x0d8
                   ("SystemAffinityActive", "B"), # UCHAR SystemAffinityActive // +0x0dc
                   ("PowerState", "B"), # UCHAR PowerState // +0x0dd
                   ("NpxIrql", "B"), # UCHAR NpxIrql // +0x0de
                   ("InitialNode", "B"), # UCHAR InitialNode // +0x0df
                   ("ServiceTable", "I"), # PVOID ServiceTable // +0x0e0
                   ("Queue", "I"), # PKQUEUE Queue // +0x0e4
                   ("ApcQueueLock", "I"), # ULONG ApcQueueLock // +0x0e8
                   ("Dummy", "4s"), # KTIMER Timer // +0x0f0
                   ("Timer", "40s"), # KTIMER Timer // +0x0f0
                   ("QueueListEntry", "2I"), # LIST_ENTRY QueueListEntry // +0x118
                   ("SoftAffinity", "I"), # ULONG SoftAffinity // +0x120
                   ("Affinity", "I"), # ULONG Affinity // +0x124
                   ("Preempted", "B"), # UCHAR Preempted // +0x128
                   ("ProcessReadyQueue", "B"), # UCHAR ProcessReadyQueue // +0x129
                   ("KernelStackResident", "B"), # UCHAR KernelStackResident // +0x12a
                   ("NextProcessor", "B"), # UCHAR NextProcessor // +0x12b
                   ("CallbackStack", "I"), # PVOID CallbackStack // +0x12c
                   ("Win32Thread", "I"), # PVOID Win32Thread // +0x130
                   ("TrapFrame", "I"), # PKTRAP_FRAME TrapFrame // +0x134
                   ("ApcStatePointer", "2I"), # PKAPC_STATE ApcStatePointer[2] // +0x138
                   ("PreviousMode", "b"), # CHAR PreviousMode // +0x140
                   ("EnableStackSwap", "B"), # UCHAR EnableStackSwap // +0x141
                   ("LargeStack", "B"), # UCHAR LargeStack // +0x142
                   ("ResourceIndex", "B"), # UCHAR ResourceIndex // +0x143
                   ("KernelTime", "I"), # ULONG KernelTime // +0x144
                   ("UserTime", "I"), # ULONG UserTime // +0x148
                   ("SavedApcState", KAPC_STATE), # KAPC_STATE SavedApcState // +0x14c
                   ("Alertable", "B"), # UCHAR Alertable // +0x164
                   ("ApcStateIndex", "B"), # UCHAR ApcStateIndex // +0x165
                   ("ApcQueueable", "B"), # UCHAR ApcQueueable // +0x166
                   ("AutoAlignment", "B"), # UCHAR AutoAlignment // +0x167
                   ("StackBase", "I"), # PVOID StackBase // +0x168
                   ("SuspendApc", "48s"), # KAPC SuspendApc // +0x16c
                   ("SuspendSemaphore", "20s"), # KSEMAPHORE SuspendSemaphore // +0x19c
                   ("ThreadListEntry", "2I"), # LIST_ENTRY ThreadListEntry // +0x1b0
                   ("FreezeCount", "b"), # CHAR FreezeCount // +0x1b8
                   ("SuspendCount", "b"), # CHAR SuspendCount // +0x1b9
                   ("IdealProcessor", "B"), # UCHAR IdealProcessor // +0x1ba
                   ("DisableBoost", "B") # UCHAR DisableBoost // +0x1bb
                 ]



class KPRCB( StructuredData):
    attributes = [ ("MinorVersion", "H"), # USHORT MinorVersion // +0x000
                   ("MajorVersion", "H"), # USHORT MajorVersion // +0x002
                   ("CurrentThread", P(KTHREAD)), #PKTHREAD), # PKTHREAD CurrentThread // +0x004
                   # Windows defines this to be a PKTHREAD, which is really just the start of an
                   # ETHREAD structure. We use KTHREAD nonetheless, as the info in ETHREAD is not
                   # all that important, and ETHREAD is a rather convoluted structure with lots of
                   # unions
                   ("NextThread", "I"), #PKTHREAD), # PKTHREAD NextThread // +0x008
                   ("IdleThread", "I"), #PKTHREAD), # PKTHREAD IdleThread // +0x00c
                   ("Number", "b"), # CHAR Number // +0x010
                   ("Reserved", "b"), # CHAR Reserved // +0x011
                   ("BuildType", "H"), # USHORT BuildType // +0x012
                   ("SetMember", "I"), # ULONG SetMember // +0x014
                   ("CpuType", "b"), # CHAR CpuType // +0x018
                   ("CpuID", "b"), # CHAR CpuID // +0x019
                   ("CpuStep", "H"), # USHORT CpuStep // +0x01a
                   ("ProcessorState", "800s"), # _KPROCESSOR_STATE ProcessorState // +0x01c
                   ("KernelReserved", "64s"), # ULONG KernelReserved[16] // +0x33c
                   ("HalReserved", "64s"), # ULONG HalReserved[16] // +0x37c
                   ("PrcbPad0", "92s"), # UCHAR PrcbPad0[92] // +0x3bc
                   ("LockQueue", "128s"), # _KSPIN_LOCK_QUEUE LockQueue[16] // +0x418
                   ("PrcbPad1", "8s"), # UCHAR PrcbPad1[8] // +0x498
                   ("NpxThread", "I"), #PKTHREAD), # PKTHREAD NpxThread // +0x4a0
                   ("InterruptCount", "I"), # ULONG InterruptCount // +0x4a4
                   ("KernelTime", "I"), # ULONG KernelTime // +0x4a8
                   ("UserTime", "I"), # ULONG UserTime // +0x4ac
                   ("DpcTime", "I"), # ULONG DpcTime // +0x4b0
                   ("DebugDpcTime", "I"), # ULONG DebugDpcTime // +0x4b4
                   ("InterruptTime", "I"), # ULONG InterruptTime // +0x4b8
                   ("AdjustDpcThreshold", "I"), # ULONG AdjustDpcThreshold // +0x4bc
                   ("PageColor", "I"), # ULONG PageColor // +0x4c0
                   ("SkipTick", "I"), # ULONG SkipTick // +0x4c4
                   ("MultiThreadSetBusy", "B"), # UCHAR MultiThreadSetBusy // +0x4c8
                   ("Spare2", "3s"), # UCHAR Spare2[3] // +0x4c9
                   ("ParentNode", "I"), # PKNODE ParentNode // +0x4cc
                   ("MultiThreadProcessorSet", "I"), # ULONG MultiThreadProcessorSet // +0x4d0
                   ("MultiThreadSetMaster", "I"), # FIXME PKPRCB MultiThreadSetMaster // +0x4d4
                   ("ThreadStartCount", "8s"), # ULONG ThreadStartCount[2] // +0x4d8
                   ("CcFastReadNoWait", "I"), # ULONG CcFastReadNoWait // +0x4e0
                   ("CcFastReadWait", "I"), # ULONG CcFastReadWait // +0x4e4
                   ("CcFastReadNotPossible", "I"), # ULONG CcFastReadNotPossible // +0x4e8
                   ("CcCopyReadNoWait", "I"), # ULONG CcCopyReadNoWait // +0x4ec
                   ("CcCopyReadWait", "I"), # ULONG CcCopyReadWait // +0x4f0
                   ("CcCopyReadNoWaitMiss", "I"), # ULONG CcCopyReadNoWaitMiss // +0x4f4
                   ("KeAlignmentFixupCount", "I"), # ULONG KeAlignmentFixupCount // +0x4f8
                   ("KeContextSwitches", "I"), # ULONG KeContextSwitches // +0x4fc
                   ("KeDcacheFlushCount", "I"), # ULONG KeDcacheFlushCount // +0x500
                   ("KeExceptionDispatchCount", "I"), # ULONG KeExceptionDispatchCount // +0x504
                   ("KeFirstLevelTbFills", "I"), # ULONG KeFirstLevelTbFills // +0x508
                   ("KeFloatingEmulationCount", "I"), # ULONG KeFloatingEmulationCount // +0x50c
                   ("KeIcacheFlushCount", "I"), # ULONG KeIcacheFlushCount // +0x510
                   ("KeSecondLevelTbFills", "I"), # ULONG KeSecondLevelTbFills // +0x514
                   ("KeSystemCalls", "I"), # ULONG KeSystemCalls // +0x518
                   ("SpareCounter0", "I"), # ULONG SpareCounter0[1] // +0x51c
                   ("PPLookasideList", "128s"), # _PP_LOOKASIDE_LIST PPLookasideList[16] // +0x520
                   ("PPNPagedLookasideList", "256s"), # _PP_LOOKASIDE_LIST PPNPagedLookasideList[32] // +0x5a0
                   ("PPPagedLookasideList", "256s"), # _PP_LOOKASIDE_LIST PPPagedLookasideList[32] // +0x6a0
                   ("PacketBarrier", "I"), # ULONG PacketBarrier // +0x7a0
                   ("ReverseStall", "I"), # ULONG ReverseStall // +0x7a4
                   ("IpiFrame", "I"), # PVOID IpiFrame // +0x7a8
                   ("PrcbPad2", "52s"), # UCHAR PrcbPad2[52] // +0x7ac
                   ("CurrentPacket", "12s"), # PVOID CurrentPacket[3] // +0x7e0
                   ("TargetSet", "I"), # ULONG TargetSet // +0x7ec
                   ("WorkerRoutine", "I"), # PVOID WorkerRoutine // +0x7f0
                   ("IpiFrozen", "I"), # ULONG IpiFrozen // +0x7f4
                   ("PrcbPad3", "40s"), # UCHAR PrcbPad3[40] // +0x7f8
                   ("RequestSummary", "I"), # ULONG RequestSummary // +0x820
                   ("SignalDone", "I"), # FIXME PKPRCB SignalDone // +0x824
                   ("PrcbPad4", "56s"), # UCHAR PrcbPad4[56] // +0x828
                   ("DpcListHead", "8s"), # _LIST_ENTRY DpcListHead // +0x860
                   ("DpcStack", "I"), # PVOID DpcStack // +0x868
                   ("DpcCount", "I"), # ULONG DpcCount // +0x86c
                   ("DpcQueueDepth", "I"), # ULONG DpcQueueDepth // +0x870
                   ("DpcRoutineActive", "I"), # ULONG DpcRoutineActive // +0x874
                   ("DpcInterruptRequested", "I"), # ULONG DpcInterruptRequested // +0x878
                   ("DpcLastCount", "I"), # ULONG DpcLastCount // +0x87c
                   ("DpcRequestRate", "I"), # ULONG DpcRequestRate // +0x880
                   ("MaximumDpcQueueDepth", "I"), # ULONG MaximumDpcQueueDepth // +0x884
                   ("MinimumDpcRate", "I"), # ULONG MinimumDpcRate // +0x888
                   ("QuantumEnd", "I"), # ULONG QuantumEnd // +0x88c
                   ("PrcbPad5", "16s"), # UCHAR PrcbPad5[16] // +0x890
                   ("DpcLock", "I"), # ULONG DpcLock // +0x8a0
                   ("PrcbPad6", "28s"), # UCHAR PrcbPad6[28] // +0x8a4
                   ("CallDpc", "32s"), # _KDPC CallDpc // +0x8c0
                   ("ChainedInterruptList", "I"), # PVOID ChainedInterruptList // +0x8e0
                   ("LookasideIrpFloat", "i"), # LONG LookasideIrpFloat // +0x8e4
                   ("SpareFields0", "24s"), # ULONG SpareFields0[6] // +0x8e8
                   ("VendorString", "13s"), # UCHAR VendorString[13] // +0x900
                   ("InitialApicId", "B"), # UCHAR InitialApicId // +0x90d
                   ("LogicalProcessorsPerPhysicalProcessor", "B"), # UCHAR LogicalProcessorsPerPhysicalProcessor // +0x90e
                   ("MHz", "I"), # ULONG MHz // +0x910
                   ("FeatureBits", "I"), # ULONG FeatureBits // +0x914
                   ("UpdateSignature", "q"), # _LARGE_INTEGER UpdateSignature // +0x918
                   ("NpxSaveArea", "528s"), # _FX_SAVE_AREA NpxSaveArea // +0x920
                   ("PowerState", "260s") # _PROCESSOR_POWER_STATE PowerState // +0xb30
                   ]
                   
                   
class KPCR( StructuredData):
    attributes = [ ( "NtTib", "28s"),          # _NT_TIB NtTib; // +0x000
                   ( "SelfPcr", "I"),          # PKPCR SelfPcr; // +0x01c
                   ( "Prcb", "I"),             # PKPRCB Prcb; // +0x020
                   ( "Irql", "B3x"),           # FIXME Alignment??? UCHAR Irql; // +0x024
                   ( "IRR", "I"),              # ULONG IRR; // +0x028
                   ( "IrrActive", "I"),        # ULONG IrrActive; // +0x02c
                   ( "IDR", "I"),              # ULONG IDR; // +0x030
                   ( "KdVersionBlock", "I"),   # PVOID KdVersionBlock; // +0x034
                   ( "IDT", "I"),              # PKIDTENTRY IDT; // +0x038
                   ( "GDT", "I"),              # PKGDTENTRY GDT; // +0x03c
                   ( "TSS", "I"),              # PKTSS TSS; // +0x040
                   ( "MajorVersion", "H"),     # USHORT MajorVersion; // +0x044
                   ( "MinorVersion", "H"),     # USHORT MinorVersion; // +0x046
                   ( "SetMember", "I"),        # ULONG SetMember; // +0x048
                   ( "StallScaleFactor", "I"), # ULONG StallScaleFactor; // +0x04c
                   ( "DebugActive", "B"),      # UCHAR DebugActive; // +0x050
                   ( "Number", "B"),           # UCHAR Number; // +0x051
                   ( "Spare0", "B"),           # UCHAR Spare0; // +0x052
                   ( "SecondLevelCacheAssociativity", "B"), # UCHAR SecondLevelCacheAssociativity; // +0x053
                   ( "VdmAlert", "I"),         # ULONG VdmAlert; // +0x054
                   ( "KernelReserved", "56s"), # ULONG KernelReserved[14]; // +0x058
                   ( "SecondLevelCacheSize", "I"), #ULONG SecondLevelCacheSize; // +0x090
                   ( "HalReserved", "64s"),    # ULONG HalReserved[16]; // +0x094
                   ( "InterruptMode", "I"),    # ULONG InterruptMode; // +0x0d4
                   ( "Spare1", "I"),           # FIXME, WAS: UCHAR Spare1; // +0x0d8
                   ( "KernelReserved2", "68s"), # ULONG KernelReserved2[17]; // +0x0dc
                   ( "PrcbData", KPRCB) ]      #KPRCB PrcbData; // +0x120




# --- Data structures for parsing the PE file format
MAGIC_PE32 = 0x010b
MAGIC_PE32plus = 0x020b
IMAGE_SCN_CNT_CODE =0x00000020
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_READ = 0x40000000


#FIXME not really pretty
def getUnsignedInt( backend, imagebase, va):
    try:
        result = struct.unpack( "<I", backend.read( va - imagebase,4))[0]
    except:
        print "getUnsignedInt( backend, 0x%08x, 0x%08x)" % (imagebase, va)
        raise
    return result


class PEFileFormatException( Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class GenericStruct( object):
    def __len__( self):
        if hasattr( self, "len"):
            return self.len
        else:
           raise TypeError( "object of type '%s' has no len()" % self.__class__.__name__)


class PEList( object):

    def __init__( self, pe_obj, offset, format = None, len = None):
        self.pe_obj = pe_obj
        self.offset = offset
        if None != format:
            self.format = format

        if not hasattr( self, "format"):
            raise Exception( "StringBackedList or subtypes thereof require a format to be specified,\n" \
                           + "either by defining a class attribute, or the format argument to __init__()")
        self.len = len
        self.itemsize = struct.calcsize( self.format)

    def __getitem__( self, index):
        if None != self.len and index >= self.len:
            raise IndexError( "list index out of range")
        offset = self.offset + index * self.itemsize
        (item,) = struct.unpack( "<" + self.format, self.pe_obj.backend.read( offset, self.itemsize))
        return item

    def __setitem__( self, index, value):
        if None != self.len and index >= self.len:
            raise IndexError( "list index out of range")
        offset = self.offset + index * self.itemsize
        replacement = struct.pack( "<" + self.format, value)
        self.pe_obj.backend.write( offset, replacement)

    def __len__( self):
        return self.len


    def index( self, item):
        for i in range( self.len):
            if self[ i] == item:
                break

        if self[ i] != item:
            raise ValueError( "list.index(): %s not in list" % item)
        else:
            return i

class PEHeaderSubstructure( StructuredData):
    def __init__( self, pe_obj, offset):
        self.offset = offset
        self.pe_obj = pe_obj
        if issubclass(self.pe_obj.__class__, PE):
            StructuredData.__init__( self, self.pe_obj.backend, offset)
        else:
            # hack to be able to instantiate Import Directory Entries with arbitrary backends
            # pe_obj then is _not_ really a PE object
            StructuredData.__init__( self, self.pe_obj, offset)

class EXEHeader( PEHeaderSubstructure):
    # Parse the EXE Header:
    # Offset Size Field
    #      0    2 Signature "MZ"
    #      2   58 Irrelevant data
    #     60    4 PESignatureOffset
    attributes = [ ( "Signature", "2s"),
                   ( "Irrelevant", "58s"),
                   ( "PESignatureOffset", "I")]

class COFFFileHeader( PEHeaderSubstructure):
    # COFF File Header
    # Offset Size Field
    #      0    2 Machine
    #      2    2 NumberOfSections
    #      4    4 TimeAndDateStamp
    #      8    4 PointerToSymbolTable
    #     12    4 NumberOfSymbols
    #     16    2 SizeOfOptionalHeader
    #     18    2 Characteristics
    attributes = [ ( "Machine", "H"),
                   ( "NumberOfSections", "H"),
                   ( "TimeAndDateStamp", "I"),
                   ( "PointerToSymbolTable", "I"),
                   ( "NumberOfSymbols", "I"),
                   ( "SizeOfOptionalHeader", "H"),
                   ( "Characteristics", "H")]
 
class OptionalHeaderStandardFields( PEHeaderSubstructure):
    # Optional Header Standard Fields
    # Offset Size Field
    #      0    2 Magic
    #      2    1 MajorLinkerVersion
    #      3    1 MinorLinkerVersion
    #      4    4 SizeOfCode
    #      8    4 SizeOfInitializedData
    #     12    4 SizeOfUninitializedData
    #     16    4 AddressOfEntryPoint
    #     20    4 BaseOfCode
    #     24    4 BaseOfData (PE32 only)
   attributes = [ ( "Magic", "H"),
                  ( "MajorLinkerVersion", "B"),
                  ( "MinorLinkerVersion", "B"),
                  ( "SizeOfCode", "I"),
                  ( "SizeOfInitializedData", "I"),
                  ( "SizeOfUninitializedData", "I"),
                  ( "AddressOfEntryPoint", "I"),
                  ( "BaseOfCode", "I"),
                  ( "BaseOfData", "I" )]

   def __init__( self, pe_obj, offset):
        self.pe_obj = pe_obj
        self.offset = offset
        format = self.attributes[ 0][ 1]
        size = struct.calcsize( format)
        s = self.pe_obj.backend.read( offset, size)
        (magic,) = struct.unpack ( "<" + format, s)
        if MAGIC_PE32 == magic:
            pass
        elif MAGIC_PE32plus == magic:
        # PE32+ files don't have a BaseOfData field in the Optional Header
            self.attributes = self.attributes[ : -1]
        else:
            raise PEFileFormatException( "Optional Header Magic 0x%04x is neither PE32 nor PE32+" % magic)
        PEHeaderSubstructure.__init__( self, self.pe_obj, self.offset)

class OptionalHeaderWindowsSpecificFields( PEHeaderSubstructure):
    # Optional Header Windows-Specific Fields
    # Offsets here are offsets within the optional header (PE32/PE32+)
    # Offset Size Field
    #  28/24  4/8 ImageBase
    #     32    4 SectionAlignment
    #     36    4 FileAlignment
    #     40    2 MajorOperatingSystemVersion
    #     42    2 MinorOperatingSystemVersion
    #     44    2 MajorImageVersion
    #     46    2 MinorImageVersion
    #     48    2 MajorSubsystemVersion
    #     50    2 MinorSubsystemVersion
    #     52    4 Win32VersionValue
    #     56    4 SizeOfImage
    #     60    4 SizeOfHeaders
    #     64    4 CheckSum
    #     68    2 Subsystem
    #     70    2 DllCharacteristics
    #     72  4/8 SizeOfStackReserve
    #  76/80  4/8 SizeOfStackCommit
    #  80/88  4/8 SizeOfHeapReserve
    #  84/96  4/8 SizeOfHeapCommit
    # 88/104    4 LoaderFlags
    # 92/108    4 NumberOfRvaAndSizes
    attributes =  [ ( "ImageBase", "I"),
                    ( "SectionAlignment", "I"),
                    ( "FileAlignment", "I"),
                    ( "MajorOperatingSystemVersion", "H"),
                    ( "MinorOperatingSystemVersion", "H"),
                    ( "MajorImageVersion", "H"),
                    ( "MinorImageVersion", "H"),
                    ( "MajorSubsystemVersion", "H"),
                    ( "MinorSubsystemVersion", "H"),
                    ( "Win32VersionValue", "I"),
                    ( "SizeOfImage", "I"),
                    ( "SizeOfHeaders", "I"),
                    ( "CheckSum", "I"),
                    ( "Subsystem", "H"),
                    ( "DllCharacteristics", "H"),
                    ( "SizeOfStackReserve", "I"),
                    ( "SizeOfStackCommit", "I"),
                    ( "SizeOfHeapReserve", "I"),
                    ( "SizeOfHeapCommit", "I"),
                    ( "LoaderFlags", "I"),
                    ( "NumberOfRvaAndSizes", "I") ]

    def __init__( self, pe_obj, offset):
        self.pe_obj = pe_obj
        self.offset = offset
        if MAGIC_PE32 == self.pe_obj.Headers.OptionalHeader.Standard.Magic:
            pass
        elif MAGIC_PE32plus == self.pe_obj.Headers.OptionalHeader.Standard.Magic:
            # Could've used fixed offsets, but this is more verbose:
            for i in range( len( self.attributes)):
                if "ImageBase" == self.attributes[ i][ 0]: 
                    self.attributes[ i] = ( "ImageBase", "Q")
                elif "SizeOfStackReserve" == self.attributes[ i][ 0]: 
                    self.attributes[ i] = ( "SizeOfStackReserve", "Q")
                elif "SizeOfStackCommit" == self.attributes[ i][ 0]:
                    self.attributes[ i] = ( "SizeOfStackCommit", "Q")
                elif "SizeOfHeapReserve" == self.attributes[ i][ 0]: 
                    self.attributes[ i] = ( "SizeOfHeapReserve", "Q")
                elif "SizeOfHeapCommit" == self.attributes[ i][ 0]: 
                    self.attributes[ i] = ( "SizeOfHeapCommit", "Q")
        else:
            pass
        # FIXME
        StructuredData.__init__( self, self.pe_obj.backend, self.offset)

class DataDirectory( PEHeaderSubstructure):

    attributes = [ ("VirtualAddress", "I"),
                   ("Size", "I")]


class OptionalHeaderDataDirectories( object):
    # Optional Header Data Directories
    # Offsets here are offsets within the optional header (PE32/PE32+)
    #  Offset Size Field
    #  96/112    8 ExportTable
    # 104/120    8 ImportTable
    # 112/128    8 ResourceTable
    # 120/136    8 ExceptionTable
    # 128/144    8 CertificateTable
    # 136/152    8 BaseRelocationTable
    # 144/160    8 Debug
    # 152/168    8 Architecture
    # 160/176    8 GlobalPtr
    # 168/184    8 TLSTable
    # 176/192    8 LoadConfigTable
    # 184/200    8 BoundImport
    # 192/208    8 IAT
    # 200/216    8 DelayImportDescriptor
    # 208/224    8 CLRRuntimeHeader
    # 216/232    8 ReservedAndZero


    names = ( 
        "ExportTable", 
        "ImportTable", 
        "ResourceTable", 
        "ExceptionTable",
        "CertificateTable",
        "BaseRelocationTable",
        "Debug",
        "Architecture",
        "GlobalPtr",
        "TLSTable",
        "LoadConfigTable",
        "BoundImport",
        "IAT",
        "DelayImportDescriptor",
        "CLRRunTimeHeader",
        "ReservedAndZero")

    def __init__( self, pe_obj):

        # Parse a maximum of 16 Data Directories
        self.pe_obj = pe_obj
        self.offset = self.pe_obj.Headers.OptionalHeader.WindowsSpecific.offset \
                    + len( self.pe_obj.Headers.OptionalHeader.WindowsSpecific)

        offset = self.offset
        
        for i in range( 0, 16):
            if i < min( self.pe_obj.Headers.OptionalHeader.WindowsSpecific.NumberOfRvaAndSizes, 16):
                directory = DataDirectory( self.pe_obj, offset)
            else:
                directory = None

            setattr( self, self.names[ i], directory)
            offset += 8

        self.len = min( self.pe_obj.Headers.OptionalHeader.WindowsSpecific.NumberOfRvaAndSizes, 16) * 8

    def __len__( self):
            return self.len

    def raw( self):
        return self.pe_obj.backend.read( self.offset, self.len)

class SectionHeader( PEHeaderSubstructure):
    # Parse Section Headers       
    # Offset Size Field
    #      0    8 Name
    #      8    4 VirtualSize
    #     12    4 VirtualAddress
    #     16    4 SizeOfRawData
    #     20    4 PointerToRawData
    #     24    4 PointerToRelocations
    #     28    4 PointerToLineNumbers
    #     32    2 NumberOfRelocations
    #     34    2 NumberOfLineNumbers
    #     36    4 Characteristics
    attributes = [ ( "Name", "8s"),
                   ( "VirtualSize", "I"),
                   ( "VirtualAddress", "I"),
                   ( "SizeOfRawData", "I"),
                   ( "PointerToRawData", "I"),
                   ( "PointerToRelocations", "I"),
                   ( "PointerToLineNumbers", "I"),
                   ( "NumberOfRelocations", "H"),
                   ( "NumberOfLineNumbers", "H"),
                   ( "Characteristics", "I")]



class SectionHeaders( list):
    # FIXME implement this as a list!

    def __init__( self, pe_obj):

        list.__init__( self, [])

        self.pe_obj = pe_obj
        self.offset = self.pe_obj.Headers.COFFFileHeader.offset \
                    + len( self.pe_obj.Headers.COFFFileHeader) \
                    + self.pe_obj.Headers.COFFFileHeader.SizeOfOptionalHeader

        offset = self.offset
        for i in range( 0, self.pe_obj.Headers.COFFFileHeader.NumberOfSections):
            sct_hdr = SectionHeader( self.pe_obj, offset)
            # FIXME Skip all-zero section headers?
            if sct_hdr.all_zero():
                continue
            self.append( sct_hdr)
            offset += len( self[ i])
            # FIXME bail out on the first invalid section header
            if ( len( self.pe_obj.Headers.EXEHeader) \
               + len( self.pe_obj.Headers.COFFFileHeader) \
               + len( self.pe_obj.Headers.OptionalHeader.Standard) \
               + len( self.pe_obj.Headers.OptionalHeader.WindowsSpecific) \
               + len( self.pe_obj.Headers.OptionalHeader.DataDirectories) \
               + (offset - self.offset)) \
               > self.pe_obj.Headers.OptionalHeader.WindowsSpecific.SizeOfHeaders:
                break
            


    def raw( self):
        # FIXME only return non-zero section headers. is this ok? watch out for complications
        buf = ""
        for i in self:
            buf += i.raw()
        return buf



class PE( object):

    class RVAException(Exception):
        pass

    def extract_string( self, rva):
        s = ""
        offset = self.rva2raw( rva)
        c = self.backend.read( offset, 1)
        while c != "\0":
            s += c
            offset += 1
            c = self.backend.read( offset, 1)
        return s

    # DllBase and SizeOfImage is abstracted into backend!
    def __init__( self, backend, name, is_image = False):
        self.backend = backend
        self.name = name
        self.is_image = is_image
        self.length = len( backend)

        self.Headers = GenericStruct()

        self.Headers.EXEHeader = EXEHeader( self, 0)

        offset = self.Headers.EXEHeader.PESignatureOffset
        if ( "PE\0\0", ) != struct.unpack( "<4s", self.backend.read( offset, 4)):
            raise PEFileFormatException( "PE Signature not found")

        offset += 4
        self.Headers.COFFFileHeader = COFFFileHeader( self, offset)

        offset += len( self.Headers.COFFFileHeader)
        self.Headers.OptionalHeader = GenericStruct()
        self.Headers.OptionalHeader.Standard = OptionalHeaderStandardFields( self, offset)

        offset += len( self.Headers.OptionalHeader.Standard)
        self.Headers.OptionalHeader.WindowsSpecific = OptionalHeaderWindowsSpecificFields( self, offset)

        offset += len( self.Headers.OptionalHeader.WindowsSpecific)
        self.Headers.OptionalHeader.DataDirectories = OptionalHeaderDataDirectories( self)

        offset += len( self.Headers.OptionalHeader.DataDirectories)
        self.Headers.SectionHeaders = SectionHeaders( self)

        offset += len( self.Headers.SectionHeaders)
        self.Headers.len = offset
        try:
            self.Imports = Imports( self)
        except self.RVAException, exception:
            print exception
            self.Imports = None
        try:
            self.Exports = Exports( self)
        except self.RVAException, exception:
            print exception
            self.Exports = None

    def rva2raw( self, rva):
        # in a memory dump, rvas are equal to raw addresses
        if self.is_image:
            if rva < len( self):
                return rva
            else:
                raise self.RVAException( "RVA 0x%08x is not within the image" % rva)

        # FIXME check: can a section overlap the headers?
        if rva < len( self.Headers):
            return rva

        sct_align = self.Headers.OptionalHeader.WindowsSpecific.SectionAlignment
        sections = []

        for s in self.Headers.SectionHeaders:
            va = s.VirtualAddress
            if va % sct_align:
                raise Exception( "A section's virtual address of 0x%08x is not aligned to 0x%08x" % ( va, sct_align))
            if va > rva:
                continue
            else:
                vs = s.VirtualSize
                reminder = s.VirtualSize % sct_align
                if reminder:
                    vs += sct_align - reminder
                if rva < va + vs:
                    sections.append( s)

        if 0 == len( sections):
            raise self.RVAException( "RVA 0x%08x not found in any section" % rva)
        elif 1 != len( sections):
            for i in sections:
                print i
            raise self.RVAException( "RVA 0x%08x found in more than one section" % rva)
        elif IMAGE_SCN_CNT_UNINITIALIZED_DATA & sections[0].Characteristics:
            raise self.RVAException( "RVA 0x%08x found in an uninitialized section" % rva)
        else:
            raw = rva - sections[0].VirtualAddress + sections[ 0].PointerToRawData

        return raw

    def __len__( self):
        return self.length

class ImportDirectoryEntry( PEHeaderSubstructure):
    # Offset Size Field
    #      0    4 ImportLookupTableRVA
    #      4    4 TimeDateStamp
    #      8    4 ForwarderChain
    #     12    4 NameRVA
    #     16    4 ImportAddressTableRVA
    attributes = [ ( "ImportLookupTableRVA", "I"),
                   ( "TimeDateStamp", "I"),
                   ( "ForwarderChain", "I"),
                   ( "NameRVA", "I"),
                   ( "ImportAddressTableRVA", "I")
                  ]

    def name( self):
        if not self.all_zero():
            return self.pe_obj.extract_string( self.NameRVA)
        else:
            return None
 

class ImportLookupTableEntry( PEHeaderSubstructure):

    def __init__( self, pe_obj, offset):
        self.pe_obj = pe_obj

        if MAGIC_PE32 == self.pe_obj.Headers.OptionalHeader.Standard.Magic:
            bitmask = 0x80000000
            format_ordinal = "2xH" # Bit 30-15 must be 0
            format_rva = "I"
            format_raw = "I"
            size = 4
        elif MAGIC_PE32plus == self.pe_obj.Headers.OptionalHeader.Standard.Magic:
            bitmask = 0x8000000000000000
            format_ordinal = "6xH" # Bit 62-15 must be 0
            format_rva = "4xL" # Bit 62-31 must be 0
            format_raw = "Q"
            size = 8
        else:
            raise Exception( "This should never happen")

        (raw, ) = struct.unpack( "<" + format_raw, self.pe_obj.backend.read( offset, size))

        if (bitmask & raw):
            self.attributes = [ ( "Ordinal", format_ordinal)]
            self.by_ordinal = True
        else:
            self.attributes = [ ( "HintNameTableRVA", format_rva)]
            self.by_ordinal = False

        PEHeaderSubstructure.__init__( self, pe_obj, offset)

    def imported_name( self):
        if self.by_ordinal:
            raise Exception( "This symbol is imported by ordinal")
        else:
            try:
                return self.pe_obj.extract_string( self.HintNameTableRVA)
            except:
                raise Exception( "Hint/Name Table RVA 0x%08x is not within this image" % self.HintNameTableRVA)
    
# Same format, create an alternative name
ImportAddressTableEntry = ImportLookupTableEntry

class Imports( object):

    def __init__( self, pe_obj):
        self.pe_obj = pe_obj

        offset = self.pe_obj.Headers.OptionalHeader.DataDirectories.ImportTable.VirtualAddress
        if 0 == offset:
            return

    # FIXME consider passing rva's to __init__ methods, 
    #       maybe even re-writing pe_obj.reader to operate on rvas
        offset = self.pe_obj.rva2raw( offset)
        idsize = self.pe_obj.Headers.OptionalHeader.DataDirectories.ImportTable.Size


        self.ImportDirectoryTable = []
        ide = ImportDirectoryEntry( self.pe_obj, offset)

        # Some packers, e.g. MEW append junk directory entries beyond the import table size
        # FIXME limiting this seems to lead to missing imports though
        while not ide.all_zero(): # and len( ide) * len( self.ImportDirectoryTable) < idsize:
            self.ImportDirectoryTable.append( ide)
            offset += len( ide)
            ide = ImportDirectoryEntry( self.pe_obj, offset)


        self.ImportLookupTables = {}
        self.ImportAddressTables = {}

        for ide in self.ImportDirectoryTable:
            # the all-zero Import Directory Table Entry should signify the end of the table
            # so we break out of the loop
            # FIXME
            if ide.NameRVA == 0 and ide.ImportLookupTableRVA == 0 and ide.ImportAddressTableRVA > len( self.pe_obj.backend):
                break
            else:
                pass

            # Parse the import lookup table entries
            # FIXME: re-think exception handling?
            try:
                name = ide.name()
                self.ImportLookupTables[ name] = []
                offset = ide.ImportLookupTableRVA
                offset = self.pe_obj.rva2raw( offset)
            except: # FIXME careful about generic except:
                offset = 0
                # skip to next entry
                break

            # No Import Lookup Table?
            if 0 != offset:
                offset = self.pe_obj.rva2raw( offset)
                count = 0
                ilte = ImportLookupTableEntry( self.pe_obj, offset)

                while not ilte.all_zero():
                    self.ImportLookupTables[ ide.name()].append( ilte)
                    offset += len( ilte)
                    ilte = ImportLookupTableEntry( self.pe_obj, offset)

            # Parse the import address table entries
            self.ImportAddressTables[ ide.name()] = []
            offset = ide.ImportAddressTableRVA
            # No Import Lookup Table?
            if 0 != offset:
                offset = self.pe_obj.rva2raw( offset)
                count = 0
                iate = ImportAddressTableEntry( self.pe_obj, offset)

                while not iate.all_zero():
                    self.ImportAddressTables[ ide.name()].append( iate)
                    offset += len( iate)
                    iate = ImportAddressTableEntry( self.pe_obj, offset)

    def imported_dlls( self):
        return [ ide.name() for ide in self.ImportDirectoryTable]

class ExportDirectoryTable( PEHeaderSubstructure):
        # Single-row Export Directory Table
        # Offset Size Field
        #      0    4 Export Flags (Reserved, must be 0)
        #      4    4 Time/Date Stamp
        #      8    2 Major Version
        #     10    2 Minor Version
        #     12    4 Name RVA
        #     16    4 Ordinal Base
        #     20    4 Address Table Entries
        #     24    4 Number Of Name Pointers
        #     28    4 Export Address Table RVA
        #     32    4 Name Pointer RVA
        #     36    4 Ordinal Table RVA
        format = "LLHHLLLLLLL"
        attributes = [ ( "ExportFlags", "I"),
                       ( "TimeDateStamp", "I"),
                       ( "MajorVersion", "H"),
                       ( "MinorVersion", "H"),
                       ( "NameRVA", "I"),
                       ( "OrdinalBase", "I"),
                       ( "AddressTableEntries", "I"),
                       ( "NumberOfNamePointers", "I"),
                       ( "ExportAddressTableRVA", "I"),
                       ( "NamePointerRVA", "I"),
                       ( "OrdinalTableRVA", "I")
                     ]


class Exports( object):
    def __init__( self, pe_obj):
        self.pe_obj = pe_obj

        offset = self.pe_obj.Headers.OptionalHeader.DataDirectories.ExportTable.VirtualAddress
        self.offset = offset
        self.size = self.pe_obj.Headers.OptionalHeader.DataDirectories.ExportTable.Size
        self.end = self.pe_obj.rva2raw( self.offset + self.size)

        if 0 == offset:
            return

        offset = self.pe_obj.rva2raw( offset)
        self.ExportDirectoryTable = ExportDirectoryTable( self.pe_obj, offset)

        offset = self.ExportDirectoryTable.ExportAddressTableRVA
        if 0 != offset:
            offset = self.pe_obj.rva2raw( offset)
            self.ExportAddressTable = PEList( self.pe_obj, offset, "I", self.ExportDirectoryTable.AddressTableEntries)

        offset = self.ExportDirectoryTable.NamePointerRVA
        if 0 != offset:
            offset = self.pe_obj.rva2raw( offset)
            self.ExportNamePointerTable = PEList( self.pe_obj, offset, "I", self.ExportDirectoryTable.NumberOfNamePointers)

        offset = self.ExportDirectoryTable.OrdinalTableRVA
        if 0 != offset:
            offset = self.pe_obj.rva2raw( offset)
            self.ExportOrdinalTable = PEList( self.pe_obj, offset, "H", self.ExportDirectoryTable.NumberOfNamePointers)

    def all_exports(self):
        exports = {}
        ordinal_base = self.ExportDirectoryTable.OrdinalBase
        image_base = self.pe_obj.Headers.OptionalHeader.WindowsSpecific.ImageBase

        # first, define exports for all addresses
        for index in xrange(self.ExportDirectoryTable.AddressTableEntries):
            ordinal = index + ordinal_base
            rva = self.ExportAddressTable[index]
            if self.is_forwarder( rva):
                forwarder = self.pe_obj.extract_string( rva)
            else:
                forwarder = ''
            exports[image_base + self.pe_obj.rva2raw(rva)] = (ordinal, rva, '', forwarder)

        # second, for those that are exported by name, update entry
        for index in xrange(self.ExportDirectoryTable.NumberOfNamePointers):
            name = self.pe_obj.extract_string(self.ExportNamePointerTable[index])
            ordinal = self.ExportOrdinalTable[ index]
            rva = self.ExportAddressTable[ ordinal]
            ordinal += ordinal_base

            if self.is_forwarder( rva):
                forwarder = self.pe_obj.extract_string( rva)
            else:
                forwarder = ""

            va = image_base + self.pe_obj.rva2raw(rva)
            #if va in exports and exports[va][2]:
            #    print "replacing export", exports[va], "with", (ordinal, rva, name, forwarder)
            exports[va] = (ordinal, rva, name, forwarder)

        return exports


    def by_ordinal( self, ordinal):
        raw_ordinal = ordinal - self.ExportDirectoryTable.OrdinalBase

        rva = self.ExportAddressTable[ raw_ordinal]
        # Export Ordinal Table is only used for mapping names to ordinals,
        # so not every ordinal value will be found in the table
        name = ""
        if raw_ordinal in self.ExportOrdinalTable:
            index = self.ExportOrdinalTable.index( raw_ordinal)
            name = self.pe_obj.extract_string( self.ExportNamePointerTable[ index])

        if self.is_forwarder( rva):
            forwarder = self.pe_obj.extract_string( rva)
        else:
            forwarder = ""

        return (ordinal, rva, name, forwarder)


    def by_name( self, name):
        lower_bound = 0
        upper_bound = len( self.ExportNamePointerTable)
        found = False
        last = 0
        index = 1

        while not found and lower_bound != upper_bound and last != index:
            last = index
            index = (upper_bound - lower_bound) / 2 + lower_bound
            cur = self.pe_obj.extract_string( self.ExportNamePointerTable[ index])
            if name < cur:
                upper_bound = index
            elif name > cur:
                lower_bound = index
            elif name == cur:
                found = True
        if not found:
            return None

        # The PE standard document says otherwise
        # But all tools agree on this version (e.g. HT Editor, IDA Pro)
        ordinal = self.ExportOrdinalTable[ index]
        rva = self.ExportAddressTable[ ordinal]
        ordinal += self.ExportDirectoryTable.OrdinalBase

        if self.is_forwarder( rva):
            forwarder = self.pe_obj.extract_string( rva)
        else:
            forwarder = ""

        return (ordinal, rva, name, forwarder)

    def by_forwarder( self, forwarder_name):
        if not hasattr( self, "ExportAddressTable"):
            return None

        for rva in self.pe_obj.Exports.ExportAddressTable:
            if self.is_forwarder( rva):
                candidate = self.pe_obj.extract_string( rva)
                # first match wins
                if candidate.lower() == forwarder_name.lower():
                    return self.by_rva( rva)
        return None

    def is_forwarder( self, rva):
        return rva >= self.offset and rva < self.offset + self.size

    def by_va( self, va):
        rva = va - self.pe_obj.Headers.OptionalHeader.WindowsSpecific.ImageBase
        return self.by_rva( rva)


    def by_rva( self, rva):

        # FIXME correctness?
#        index = self.ExportAddressTable.index( rva)

#        raw_ordinal = self.ExportOrdinalTable.index( index)
#        name = self.pe_obj.extract_string( self.ExportNamePointerTable[ raw_ordinal])

#        ordinal = raw_ordinal + self.ExportDirectoryTable.OrdinalBase

        raw_ordinal = self.ExportAddressTable.index( rva)
        ordinal = raw_ordinal + self.ExportDirectoryTable.OrdinalBase

        try:
            ordinal_index = self.ExportOrdinalTable.index( raw_ordinal)
            name = self.pe_obj.extract_string( self.ExportNamePointerTable[ ordinal_index])
        except:
            name = ""

        ordinal = raw_ordinal + self.ExportDirectoryTable.OrdinalBase


        if self.is_forwarder( rva):
            forwarder = self.pe_obj.extract_string( rva)
        else:
            forwarder = ""

        return (ordinal, rva, name, forwarder)

class STR( object):
    def __init__( self, backend, offset):
        self.backend = backend
        self.offset = offset

    def __str__( self):
        offset = self.offset
        s = ""
        c = self.backend.read( offset, 1)
        while c != "\0":
            s += c
            offset += 1
            c = self.backend.read( offset, 1)
        return s

    def __len__( self):
        offset = 0
        c = self.backend.read( self.offset + offset, 1)
        while c != "\0":
            offset += 1
            c = self.backend.read( self.offset + offset, 1)
        return offset

class WSTR( object):
    def __init__( self, backend, offset):
        self.backend = backend
        self.offset = offset

    def __str__( self):
        offset = self.offset
        s = ""
        c = self.backend.read( offset, 2)
        while c != "\0\0":
            s += c
            offset += 2
            c = self.backend.read( offset, 2)
        return s.decode( "UTF-16LE")

    def __len__( self):
        offset = 0
        c = self.backend.read( self.offset + offset, 2)
        while c != "\0\0":
            offset += 2
            c = self.backend.read( self.offset + offset, 2)
        return offset


class VadTree( object):
    def __init__( self, process):
        self.process = process

    def get_vad_root( self): return self.process.eprocess.VadRoot
    root = property( get_vad_root)

    def inorder( self, root = None):
        if root == None:
            root = self.get_vad_root()
        if root.is_null():
            return
        else:
            root = root.deref()

        for node in self.inorder( root.LeftChild): yield node
        yield root
        for node in self.inorder( root.RightChild): yield node

    def by_address( self, address, root = None):
        if root == None:
            root = self.get_vad_root()
        if root.is_null():
            return None
        else:
            root = root.deref()
            if root.StartingVpn * PAGESIZE <= address and address < (root.EndingVpn + 1) * PAGESIZE:
                return root
            elif address < root.StartingVpn * PAGESIZE:
                return self.by_address( address, root.LeftChild)
            elif address >= (root.EndingVpn + 1) * PAGESIZE:
                return self.by_address( address, root.RightChild)
            else:
                raise Exception( "error traversing VAD tree for address 0x%08x" % address)

    def dump( self):
        print "Dumping VAD tree"
        print "----------------"
        for r in self.inorder():
            start = r.StartingVpn * PAGESIZE
            end = (r.EndingVpn + 1) * PAGESIZE - 1
            name = ""
            if not r.ControlArea.is_null():
              try:
                ca = r.ControlArea.deref()
                if not ca.FilePointer.is_null():
                  try:
                    file = ca.FilePointer.deref()
                    name = str( file.FileName)
                  except UnicodeDecodeError:
                    name = ""
                  except PageFaultException:
                    name = ""
                  except: # FIXME deref() raises a generic exception
                    name = ""
              except PageFaultException:
                 name = ""
              except: # FIXME deref() raises a generic exception
                name = ""
            print "0x%08x ... 0x%08x %s" % ( start, end, name)
        print "----------------"

