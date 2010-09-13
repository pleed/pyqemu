#!/usr/bin/python

import PyFlxInstrument
from Structures import *

# --- class Image ------------------------------------------------------
class Image( object):

    def get_entrypoint( self):
        try:
            return self.cached.entrypoint
        except:
            return self.ldr_data_table_entry.EntryPoint

    def get_sizeofimage( self):
        try:
            return self.cached.sizeofimage
        except:
            return self.ldr_data_table_entry.SizeOfImage

    def get_dllbase( self):
        try:
            return self.cached.dllbase
        except:
            return self.ldr_data_table_entry.DllBase

    def get_fulldllname( self):
        try:
            return self.cached.fulldllname
        except:
            return self.ldr_data_table_entry.FullDllName.str()

    def get_basedllname( self):
        try:
            return self.cached.basedllname
        except:
            return self.ldr_data_table_entry.BaseDllName.str()

    EntryPoint =  property( get_entrypoint)
    SizeOfImage = property( get_sizeofimage)
    DllBase =     property( get_dllbase)
    FullDllName = property( get_fulldllname)
    BaseDllName = property( get_basedllname)
    Name =        property( get_basedllname) # for compatibility with a yet-to-be-implemented general memory range class

    def __init__( self, ldr_data_table_entry, process):
        self.ldr_data_table_entry = ldr_data_table_entry
        self.process = process
        self.valid = False
        self.exports_done = False
        self.exports = {}

        self.last_executed_page = None

        self.image_type = IMAGE_TYPE_UNKNOWN

        self.cached = GenericStruct()

        self.pending_pages = set( [])
        self.dump_pending = False

        self.update()

    def update( self):
        # sanity check the LDR_DATA_TABLE_ENTRY struct:
        #  - Check whether DllBase is on a page boundary
        #  - Check whether EntryPoint is within [DllBase, DllBase+SizeOfImage) or 0
        #  - Check whether the entire DLL resides in userspace?
        #  - Check whether SizeOfImage is a multiple of the page size
        #  - Check whether SizeOfImage != 0

        valid = self.valid

        if not valid:

            valid = True
            valid = valid and not (self.ldr_data_table_entry.DllBase % PAGESIZE)
            valid = valid and self.ldr_data_table_entry.EntryPoint >= self.ldr_data_table_entry.DllBase \
                          and self.ldr_data_table_entry.EntryPoint < self.ldr_data_table_entry.DllBase + self.ldr_data_table_entry.SizeOfImage
            valid = valid and self.ldr_data_table_entry.DllBase < USER_KERNEL_SPLIT \
                          and self.ldr_data_table_entry.DllBase + self.ldr_data_table_entry.SizeOfImage < USER_KERNEL_SPLIT
            valid = valid and not (self.ldr_data_table_entry.SizeOfImage % PAGESIZE)
            valid = valid and self.ldr_data_table_entry.SizeOfImage != 0

            # if we cannot yet fetch the FullDllName, try again later
            try:
                fulldllname = self.ldr_data_table_entry.FullDllName.str()
            except PageFaultException, pagefault:
                valid = False
                self.pending_pages.add( pagefault.value[ 0] / PAGESIZE)
                #PyBochsC.pending_page( True)


        if not self.valid and valid:
            # this image was previously not valid, but is now, so it must be new

            if self.BaseDllName.startswith( self.process.eprocess.ImageFileName.strip( "\0")):
                print "Entrypoint is 0x%08x" % self.EntryPoint
                watchpoint = EntryPointWatchpoint( self.process, self.EntryPoint)
                self.process.watchpoints.add_function_call_watchpoint( watchpoint)

            if self.BaseDllName.lower().endswith( '.dll'):
                self.image_type = IMAGE_TYPE_DLL
            elif self.BaseDllName.lower().endswith( '.exe'):
                self.image_type = IMAGE_TYPE_EXE


        if self.valid or valid:
            self.cached.entrypoint = int( self.ldr_data_table_entry.EntryPoint)
            self.cached.sizeofimage = int( self.ldr_data_table_entry.SizeOfImage)
            self.cached.dllbase = int( self.ldr_data_table_entry.DllBase)
            self.cached.fulldllname = self.ldr_data_table_entry.FullDllName.str()
            self.cached.basedllname = self.ldr_data_table_entry.BaseDllName.str()


        if valid and self.process.watched and not hasattr( self, "pe"):
            try:
                #self.pe = PE( VMemBackend( self.DllBase,
                 #                          self.DllBase + self.SizeOfImage, 
                  #                         self.process.pdb), 
                self.pe = PE( VMemBackend( self.DllBase,
                                           self.DllBase + self.SizeOfImage ),
                              self.BaseDllName, 
                              True)
                print "PE image parsed for %s" % self.FullDllName
            except PageFaultException, pagefault:
                self.pending_pages.add( pagefault.value[ 0] / PAGESIZE)
                #PyBochsC.pending_page( True)

        if valid and not self.exports_done and hasattr( self, "pe") and hasattr( self.pe.Exports, "ExportAddressTable"):
            try:
                self.exports.update(self.pe.Exports.all_exports())
                self.process.symbols.update(self.exports)
                self.exports_done = True
            except PageFaultException, pagefault:
                self.pending_pages.add( pagefault.value[ 0] / PAGESIZE)
                #PyBochsC.pending_page( True)

        if not self.valid and valid and self.process.watched:
            self.dump_pending = True
            pending = False
            for page in xrange( self.DllBase, self.DllBase + self.SizeOfImage, PAGESIZE):
                try:
                    dummy = self.process.backend.read( page, 1)
                except:
                    self.pending_pages.add( page / PAGESIZE)
                    pending = True
            if pending:
                #PyBochsC.pending_page( True)
                pass
            self.valid = valid

    def dump( self):
        start = self.DllBase
        size = self.SizeOfImage
        time = 0

        try:
            data = PyFlxInstrument.vmem_read( start, size)
            tag = self.FullDllName
            for p in xrange( start / PAGESIZE, (start + size) / PAGESIZE ):
                if p in self.process.writes:
                    self.process.writes[ p].last_dumped = time
                else:
                    self.process.writes[ p] = ModifiedPage( self, p)
                    self.process.writes[ p].last_dumped = time
            self.dump_pending = False
        except PageFaultException, pagefault:
            self.pending_pages.add( pagefault.value[ 0] / PAGESIZE)
            #PyBochsC.pending_page( True)


# --- class Process ----------------------------------------------------
class Process( object):

    def get_pid( self): return self.eprocess.UniqueProcessId
    pid = property( get_pid)

    def get_ppid( self): return self.eprocess.InheritedFromUniqueProcessId
    ppid = property( get_ppid)

    def get_cur_tid(self): 
        teb = self.kpcr.PrcbData.CurrentThread.deref().Teb
        if teb.is_null():
            return -1
        return teb.deref().ClientId.UniqueThread
    cur_tid = property(get_cur_tid)

    def get_imagefilename( self): return self.eprocess.ImageFileName
    ImageFileName = property( get_imagefilename)

    def check_update_pending( self): return not self.valid or self.last_updated < self.last_seen
    update_pending = property( check_update_pending)

    def innovate( self):
        self.innovated = True


    def innovates( function):
        #function decorator
        def innovating_wrapper( self, *args, **kwargs):
            self.innovate()
            function( *args, **kwargs)
        return innovating_wrapper


    def ev_write( self, address, size):
        # Convention: This is only called if the process is watched
        # Writes from kernel space code should not be of interest
        eip = PyFlxInstrument.eip()
        if eip < USER_KERNEL_SPLIT and address + size < USER_KERNEL_SPLIT: # FIXME investigate: why is the write target limitation here?

            self.shortterm_writes.add( address/256)

            page = address / PAGESIZE
            if page not in self.writes:
                self.writes[ page] = ModifiedPage( self, page)

            self.writes[ page].write(eip, address, size) # FIXME do we care about spilling writes across two pages?
            return -1 # if the process is watched, we want to take note of writes happening from userspace code
        else:
            return 0

    def dump_range( self, address):
        # TODO:
        # really dump ranges, attach tags, dump whole images if range falls within image

        time = 0 #PyBochsC.emulator_time()

        vad = self.vad_tree.by_address( address)

        if vad != None:
            start = vad.StartingVpn * PAGESIZE
            end = (vad.EndingVpn + 1) * PAGESIZE
            size = end-start
            try:
                t = DUMP_IMAGE
                tag = vad.ControlArea.deref().FilePointer.deref().FileName.str()
            except:
                # Maybe packers like morphine modified the module lists for us?
                image = self.get_image_by_address( address)
                if image:
                    t = DUMP_IMAGE
                    tag = image.BaseDllName
                else:
                    t = DUMP_UNSPECIFIED
                    tag = "anonymous"

            try:
                data = PyFlxInstrument.vmem_read( start, size)
                t |= DUMP_FULL

            except PageFaultException, pagefault:
                print "Page fault when trying to dump", pagefault
                # zero-pad missing memory
                data = ""
                print "trying to dump from 0x%08x to 0x%08x" % (start, end)
                for i in xrange( start, end, PAGESIZE):
                    try:
                        data += PyFlxInstrument.vmem_read( i, PAGESIZE)
                    except PageFaultException:
                        data += '\0' * PAGESIZE
                t |= DUMP_PARTIAL

            # clear the sets:
            page = address / PAGESIZE
            writers = self.writes[ page].writers.copy()
            while page in self.writes:
                del self.writes[page]
                page -= 1

            page = address / PAGESIZE + 1 #self.writes[address/PAGESIZE] already clear
            while page in self.writes:
                del self.writes[page]
                page += 1

            print "about to insert a %u byte dump into the database, with type %u and tag %s" %( len(data), t, tag)
        else:
            raise Exception( "Executing non-existing memory?")

    def pending_page( self):
        if len( self.pending_pages) > 0:
            return self.pending_pages.pop() * PAGESIZE
        else:
            for base in self.images:
                if len( self.images[ base].pending_pages) > 0:
                    return self.images[ base].pending_pages.pop() * PAGESIZE
                elif self.images[ base].dump_pending:
                    self.images[ base].dump()
        #PyBochsC.pending_page( False)
        return None

    def print_stack( self, function, source, offset = 0):
        function_name = function.name
        ESP = PyFlxInstrument.genreg(PyBochsC.REG_ESP)
        function_definition = []
        for arg in function.arguments:
            if type(arg.type) == pygccxml.declarations.cpptypes.pointer_t:
                if str(arg.type.base) in ('xxxchar', 'char const'):
                    t = P(STR)
                elif str(arg.type.base) in ('xxxwchar_t', 'wchar_t const'):
                    t = P(WSTR)
                else:
                    t = "I"
            elif type(arg.type) in (pygccxml.declarations.typedef.typedef_t, pygccxml.declarations.cpptypes.declarated_t):
                if arg.type.declaration.name in ('LPCSTR', 'xxxLPSTR'):
                    t = P(STR)
                elif arg.type.declaration.name in ('LPCWSTR','xxxLPWSTR'):
                    t = P(WSTR)
                else:
                    dwords = arg.type.byte_size / 4
                    t = "I" * dwords # FIXME
            else:
                dwords = arg.type.byte_size / 4
                t = "I" * dwords # FIXME
            arg_definition = (arg.name, t)
            function_definition.append(arg_definition)
        stack = Stack(function_definition)( self.backend, ESP + offset)
        output = []
        for arg_def in function_definition:
            arg = getattr( stack, arg_def[ 0])
            if hasattr( arg, "deref"):
                try:
                    output.append(u"%s = %s" % (arg_def[0], arg.deref()))
                except PageFaultException:
                    output.append("%s = !0x%08x" % (arg_def[0], arg.offset))
                except UnicodeEncodeError:
                    s = arg.deref()
                    output.append(u"%s = %s %u %s" % (arg_def[0],'+++',len(arg.deref()),unicode(s).encode('utf-8')))
                except UnicodeDecodeError:
                    s = arg.deref()
                    str(s)
                    output.append(u"%s = %s %u %r" % (arg_def[0],'---',len(arg.deref()),str(s))) # FIXME UNICODE DECODE ERRORS
            else:
                output.append(u"%s = %s" % (arg_def[0], arg))
        foo = u', '.join(output)
        if offset:
            print u"PPID %u/PID %u/TID %u/STOLEN/0x%08x -> %s(%r)" % (self.ppid,self.pid,self.cur_tid,source,unicode(function_name), foo)# FIXME UNICODE DECODE ERRORS
        else:
            print u"PPID %u/PID %u/TID %u/0x%08x -> %s(%r)" % (self.ppid,self.pid,self.cur_tid,source,unicode(function_name), foo)# FIXME UNICODE DECODE ERRORS



    def ev_branch( self, source, target, type):
        # Convention: This is only called if the process is watched
        if target < USER_KERNEL_SPLIT:

            self.watchpoints.visit_location( target)
            self.shortterm_branches.add( target/256)
            func = None

            source_image = self.get_image_by_address(source)
            target_image = self.get_image_by_address(target)

            if source_image == target_image:
                pass
            elif (source_image and source_image.DllBase == self.eprocess.Peb.deref().ImageBaseAddress and target_image) \
              or (not source_image and target_image):
                # store branches from within the image to other memory (for import reconstruction)
                if target in self.symbols:
                    function_name = self.symbols[target][2]
                    if target not in self.gccxml_cache and function_name not in self.unknown_symbols:
                        self.innovate() # new, unknown branch target
                        try:
                            func = namespace.free_function(name=function_name)
                            self.gccxml_cache[target] = func
                        except pygccxml.declarations.matcher.declaration_not_found_t:
                            self.unknown_symbols.append(function_name)
                        except pygccxml.declarations.matcher.multiple_declarations_found_t:
    #                        print "multiple matches for function '%s()'" % function_name
                            func = namespace.free_functions(name=function_name)[0]
                            self.gccxml_cache[target] = func
                    elif target in self.gccxml_cache:
                        func = self.gccxml_cache[target]
                    if func:
                        self.print_stack(func, source)
                elif target not in self.symbols and source < USER_KERNEL_SPLIT: # kernel returns to userland addresses, but there's normally no symbol there
                    # interesting, target seems to be within a DLL, but there's no symbol at that address
                    # stolen bytes?
                    earlier_symbols = [address for address in self.symbols.keys() if address < target]
                    earlier_symbols.sort()
                    if earlier_symbols:
                        orig_target = target
                        target = earlier_symbols[-1]
                        address = target
                        stack_offset = 0
                        invalid = False
                        while address < orig_target:
                            insn = pydasm.get_instruction( PyFlxInstrument.vmem_read( address, 50, self.pdb), pydasm.MODE_32) # FIXME use real x86 instruction length limit here
                            #print pydasm.get_instruction_string(insn, pydasm.FORMAT_INTEL, address), insn.op1.reg, insn.op2.reg, insn.op3.reg
                            if not insn:
                                invalid = True
                                break
                            elif insn and insn.op1.reg == pydasm.REGISTER_ESP:
                                invalid = True # ESP is destroyed
                            elif insn.type == pydasm.INSTRUCTION_TYPE_POP:
                                stack_offset -= 4
                            elif insn.type == pydasm.INSTRUCTION_TYPE_PUSH:
                                stack_offset += 4
                            elif insn.type == pydasm.INSTRUCTION_TYPE_RET:
                                invalid = True # indicator of function boundary -> no luck for us
                            address += insn.length
                        candidate = self.symbols[target]
                        function_name = candidate[2]
                        if not invalid:
                            if target not in self.gccxml_cache and function_name not in self.unknown_symbols:
                                self.innovate() # new, unknown branch target
                                try:
                                    func = namespace.free_function(name=function_name)
                                    self.gccxml_cache[target] = func
                                except pygccxml.declarations.matcher.declaration_not_found_t:
                                    self.unknown_symbols.append(function_name)
                                except pygccxml.declarations.matcher.multiple_declarations_found_t: 
                                    # multiple matches
                                    func = namespace.free_functions(name=function_name)[0]
                                    self.gccxml_cache[target] = func
                            elif target in self.gccxml_cache:
                                func = self.gccxml_cache[target]
                            if func:
                                self.print_stack(func, source, stack_offset)
                        else:
                            print "0x%08x -> 0x%08x: symbol at target not found, invalid candidate: %s, offset %u, image there is %s" % (source, orig_target, str(candidate),orig_target-target, target_image.BaseDllName)
                    pass
            elif source_image and source_image.DllBase != self.eprocess.Peb.deref().ImageBaseAddress:
                pass



            page = target / PAGESIZE
            if page in self.writes and target in self.writes[ page].writeset:
                self.innovate()
                print "executing 0x%08x -> 0x%08x" % (source, target)
                self.dump_range( target)
            return 1

        else:
            # not in user mode
            return 0



    def get_image_by_address( self, address):
        bases = [base for base in self.images if base <= address]
        bases.sort()
        if bases:
            image = self.images[bases[-1]]
        else:
            return None

        if address <= image.DllBase + image.SizeOfImage:
            return image
        else:
            return None

    def __init__( self):
        #self.pdb = pdb
        #linear = PyBochsC.logical2linear( 0x30, 0, pdb)
        linear = PyFlxInstrument.creg(4) #R_FS
        self.backend = VMemBackend( 0, 0x100000000)
        self.kpcr = KPCR( self.backend, linear)
        self.watched = False

        #self.watchpoints = Watchpoints( self)
        self.symbols = {}
        self.unknown_symbols = [] # insert symbols that pygccxml cannot find here
        self.gccxml_cache = {}

        self.pending_pages = set([])
        self.images = {}          # indexed by base address
        self.valid = False
        self.eprocess = None

        self.last_seen = 0
        self.last_updated = 0

        self.vad_tree = VadTree( self)

        self.writes = {}
        self.last_executed_modified_page = None
        self.innovated = False

        self.dll_locations = set( [])

        self.shortterm_writes = set( [])
        self.shortterm_branches = set( [])

        self.update()


    def check_watched( self):
        if not self.valid:
            return False

        return False #flx

        if not self.watched:
            imagefilename = self.kpcr.PrcbData.CurrentThread.deref().ApcState.Process.deref().ImageFileName
            self.watched = globals()[ "samplename"].upper().startswith( imagefilename.strip( "\0").upper())

            try:
                ppid = self.ppid
            except PageFaultException, pagefault:
                self.pending_pages.add( pagefault.value[ 0] / PAGESIZE)
                #PyBochsC.pending_page( True)
                return self.watched

            for pdb in helper.processes:
               try:
                   pid = helper.processes[ pdb].pid
               except PageFaultException, pagefault:
                   self.pending_pages.add( pagefault.value[ 0] / PAGESIZE)
                   #PyBochsC.pending_page( True)
                   continue
               except AttributeError:
                   continue

               if helper.processes[ pdb].watched and ppid == pid:
                    self.watched = True
                    break

            if self.watched:
                print "Now watching process with name '%s'" % imagefilename
                self.innovate()

        return self.watched


    def update( self):

        # Sanity check the data structures
        valid = self.valid
        if not valid:
            valid = True
            eprocess = self.kpcr.PrcbData.CurrentThread.deref().ApcState.Process.deref()

            valid = valid and eprocess.CreateTime != 0
            valid = valid and eprocess.ActiveThreads != 0
            valid = valid and (eprocess.Peb.pointer & 0x7ff00000) == 0x7ff00000 # FIXME use named constant
            valid = valid and eprocess.UniqueProcessId != 0
            valid = valid and eprocess.InheritedFromUniqueProcessId != 0

            # If all else fails, is this the System Process?
            valid = valid or eprocess.ImageFileName.startswith( "System") \
                          and eprocess.UniqueProcessId == 4 \
                          and eprocess.InheritedFromUniqueProcessId == 0

            # If all else fails, is this the Idle Process?
            valid = valid or eprocess.ImageFileName.startswith( "Idle") \
                          and eprocess.UniqueProcessId == 4 \
                          and eprocess.InheritedFromUniqueProcessId == 0


        if not self.valid and valid:
            # new process
            print "New process '%s', PID %u, PPID %u" % (eprocess.ImageFileName, eprocess.UniqueProcessId, eprocess.InheritedFromUniqueProcessId)
            # Cache eprocess - FIXME does doing this once suffice? is this even real caching( it's a StructuredData() after all)
            self.eprocess = eprocess

        if self.valid:
            self.update_images()

        self.valid = valid

        self.check_watched()
        self.last_updated = 0 #PyBochsC.emulator_time()



    def update_images( self):

        try:
            eprocess = self.kpcr.PrcbData.CurrentThread.deref().ApcState.Process.deref()
        except:
            print "Could not fetch eprocess struct for process with page directory base 0x%08x" % self.pdb
            return

        try:
            Peb = eprocess.Peb.deref()
        except:
            print "Could not fetch Peb pointed to by pointer at 0x%08x, pdb is 0x%08x" \
                  % (eprocess.Peb.offset, self.pdb)
            return

        try:
            LdrData = eprocess.Peb.deref().Ldr.deref()
        except:
            print "Could not fetch LdrData pointed to by pointer at 0x%08x, pdb is 0x%08x" \
                  % ( eprocess.Peb.deref().Ldr.offset, self.pdb)
            return

        module_list = LdrData.InMemoryOrderModuleList

        image = LdrData.InMemoryOrderModuleList.next()
        while None != image:
            if image.DllBase not in self.images:
                # a new DLL was found in memory
                self.innovate()
                self.images[ image.DllBase] = Image( image, self)
            elif not self.images[ image.DllBase].valid or not self.images[ image.DllBase].exports_done:
                self.images[ image.DllBase].update()
            elif self.watched and not hasattr( self.images[ image.DllBase], "pe"):
                self.images[ image.DllBase].update()

            image = LdrData.InMemoryOrderModuleList.next()

    def enter( self):
        if self.watched:
            w = len( self.shortterm_writes)
            b = len( self.shortterm_branches)
            ratio = b and float( w) / float( b)
            if w >= 50:
                ratio = b and float( w) / float( b)
                if ratio > 2:
                    self.innovate()
                print "writes: %8u, branch targets: %6u, ratio: %04.2f" % ( w, b, ratio)
                self.shortterm_writes.clear()
                self.shortterm_branches.clear()

        self.last_seen = 0 #PyBochsC.emulator_time()
        # PyBochsC.pending_page( self.pending_pages != [])
        if self.watched and self.innovated:
            helper.sched_nonwatched = 0
            self.innovated = False
        elif self.valid and not self.eprocess.UniqueProcessId in (0,4):
            helper.sched_nonwatched += 1
            if not helper.sched_nonwatched % 200:
                print helper.sched_nonwatched
        if helper.sched_nonwatched > LIVENESS_BOUND and CHECK_LIVENESS:
            print "No watched process appears to be live and showing progress, shutting down!"
            #PyBochsC.shutdown()
            pass

    def leave( self):
        pass
