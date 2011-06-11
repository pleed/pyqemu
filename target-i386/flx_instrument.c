/////////////////////////////////////////////////////////////////////////
// $Id: instrument.cc,v 1.16 2007/03/14 21:15:15 sshwarts Exp $
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001  MandrakeSoft S.A.
//
//    MandrakeSoft S.A.
//    43, rue d'Aboukir
//    75002 Paris - France
//    http://www.linux-mandrake.com/
//    http://www.mandrakesoft.com/
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

#include <Python.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include "cpu.h"
#include "exec-all.h"

#include "flx_instrument.h"
#include "flx_disas.h"
#include "flx_breakpoint.h"
#include "flx_memtrace.h"
#include "flx_filter.h"
#include "flx_caballero.h"
#include "flx_bbltranslate.h"
#include "flx_arithwindow.h"
#include "flx_bbltrace.h"
#include "flx_bbl.h"
#include "flx_functiontrace.h"
#include "flx_context.h"
#include "flx_functionentropy.h"
#include "flx_constsearch.h"
#include "flx_bblwindow.h"

//#ifndef DEBUG
//#define DEBUG
//#define DEBUG_SWITCHED_ON
//#endif
unsigned startup_time = 0;

#define dbg_cpu 0
// don't output debugging information from helper functions
#define dbg_printf
#define LOG_THIS

FLX_STATE flx_state;

static PyObject *Py_Python_Module;
static PyObject *PyFlx_C_Module;

//todo: register and unregister routines
PyObject *PyFlx_ev_call = NULL;
PyObject *PyFlx_ev_jmp = NULL;
PyObject *PyFlx_ev_syscall = NULL;
PyObject *PyFlx_ev_update_cr3 = NULL;
PyObject *PyFlx_ev_ret = NULL;
PyObject *PyFlx_ev_bp = NULL;
PyObject *PyFlx_ev_memtrace = NULL;
PyObject *PyFlx_ev_caballero = NULL;
PyObject *PyFlx_ev_arithwindow = NULL;
PyObject *PyFlx_ev_bblstart = NULL;
PyObject *PyFlx_ev_shutdown = NULL;
PyObject *PyFlx_ev_functiontrace = NULL;
PyObject *PyFlx_ev_functionentropy = NULL;
PyObject *PyFlx_ev_constsearch = NULL;

static PyObject *PyFlx_REG_EAX;
static PyObject *PyFlx_REG_ECX;
static PyObject *PyFlx_REG_EDX;
static PyObject *PyFlx_REG_EBX;
static PyObject *PyFlx_REG_ESP;
static PyObject *PyFlx_REG_EBP;
static PyObject *PyFlx_REG_ESI;
static PyObject *PyFlx_REG_EDI;
static PyObject *PyFlx_ISEMPTY;
static PyObject *PyFlx_ISCALL;
static PyObject *PyFlx_ISJMP;


CPUState *current_environment = NULL;
uint32_t element_counter = 0;

static PyObject* PyFlxC_filter_add(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_filter_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  uint32_t start;
  uint32_t end;
  
  if(!PyArg_ParseTuple(args, "II", &start, &end))
    return NULL;
  flx_filter_add_by_range(start,end);
  Py_INCREF(Py_None);
  return Py_None;

}

static PyObject* PyFlxC_filter_del(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_filter_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  uint32_t start;
  uint32_t end;
  if(!PyArg_ParseTuple(args, "II", &start, &end))
    return NULL;
  flx_filter_del_by_range(start,end);
  Py_INCREF(Py_None);
  return Py_None;

}

static PyObject* PyFlxC_filter_enable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_filter_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  flx_filter_enable();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_filter_disable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_filter_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  flx_filter_disable();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_bbltrace_disable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_bbltrace_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  flx_bbltrace_disable();

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_constsearch_enable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_constsearch_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif

  flx_constsearch_enable();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_constsearch_disable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_constsearch_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif

  flx_constsearch_disable();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_constsearch_search(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_constsearch_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif

  flx_constsearch_search();
  return Py_None;

}

static PyObject* PyFlxC_functiontrace_enable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_functiontrace_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif

  flx_functiontrace_enable();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_functiontrace_disable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_functiontrace_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif

  flx_functiontrace_disable();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_arithwindow_enable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_arithwindow_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   uint32_t window_size;
   float min_percentage;
   if(!PyArg_ParseTuple(args, "If", &window_size, &min_percentage))
     return NULL;

  flx_arithwindow_enable(window_size, min_percentage);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_arithwindow_disable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_arithwindow_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  flx_arithwindow_disable();

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_functionentropy_enable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_functionentropy_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   float threshold;
   if(!PyArg_ParseTuple(args, "f", &threshold))
     return NULL;

  flx_functionentropy_enable(threshold);

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_functionentropy_disable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_functionentropy_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   float threshold;
   if(!PyArg_ParseTuple(args, "f", &threshold))
     return NULL;

  flx_functionentropy_disable();

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_constsearch_pattern(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_constsearch_pattern");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   uint8_t* pattern;
   uint32_t pattern_len;
   if(!PyArg_ParseTuple(args, "s#", &pattern, &pattern_len)){
   	return Py_None;
   }

  flx_constsearch_pattern(pattern, pattern_len);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_caballero_enable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_caballero_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   uint32_t min_bbl_size;
   float min_percentage;
   if(!PyArg_ParseTuple(args, "If", &min_bbl_size, &min_percentage))
     return NULL;

  flx_caballero_enable(min_bbl_size, min_percentage);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_caballero_disable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_caballero_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  flx_caballero_disable();

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_bblwindow_get(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_bblwindow_get");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   uint32_t index;
   PyObject *retval;

   if(!PyArg_ParseTuple(args, "I", &index)) {
      // raise exception, too?
      return NULL;
   }
   uint32_t eip;
   if(flx_bblwindow_get(index, &eip) == 0){
      retval = Py_BuildValue("I", eip);
      return retval;
   }
   else{

     Py_INCREF(Py_None);
     return Py_None;
   }
}

static PyObject* PyFlxC_bblwindow_enable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_bblwindow_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  uint32_t window_size;
  if(!PyArg_ParseTuple(args, "I", &window_size)){
    return NULL;
  }
  flx_bblwindow_enable(window_size);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_bblwindow_disable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_bblwindow_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  flx_bblwindow_disable();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_bbltrace_enable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_bbltrace_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  flx_bbltrace_enable();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_memtrace_disable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_memtrace_disable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  flx_memtrace_disable();

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_memtrace_enable(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_memtrace_enable");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  flx_memtrace_enable();
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_breakpoint_delete(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_breakpoint_delete");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  uint32_t address;
  
  if(!PyArg_ParseTuple(args, "I", &address))
    return NULL;
  flx_breakpoint_delete(address, current_environment->cr[3]);
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_breakpoint_insert(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_breakpoint_insert");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  uint32_t address;
  
  if(!PyArg_ParseTuple(args, "I", &address))
    return NULL;
  flx_breakpoint_insert(address, current_environment->cr[3]);
  Py_INCREF(Py_None);
  return Py_None;
}


static PyObject* PyFlxC_registers(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "registers");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   PyObject *retval = Py_None;
   if(!PyArg_ParseTuple(args, "")) {
  	  Py_INCREF(Py_None);
      return Py_None;
   }

   if (current_environment){
     retval = Py_BuildValue(
			    "{s:I,s:I,s:I,s:I,s:I,s:I,s:I,s:I"
			    ",s:h,s:h,s:h,s:h,s:h,s:h"
			    ",s:I"
			    ",s:I,s:I,s:I,s:I"
			    ",s:I"
			    "}",
			    "eax", current_environment->regs[R_EAX],
			    "ecx", current_environment->regs[R_ECX],
			    "edx", current_environment->regs[R_EDX],
			    "ebx", current_environment->regs[R_EBX],
			    "esp", current_environment->regs[R_ESP],
			    "ebp", current_environment->regs[R_EBP],
			    "esi", current_environment->regs[R_ESI],
			    "edi", current_environment->regs[R_EDI],
			    "es", current_environment->segs[R_ES].selector,
			    "cs", current_environment->segs[R_CS].selector,
			    "ss", current_environment->segs[R_SS].selector,
			    "ds", current_environment->segs[R_DS].selector,
			    "fs", current_environment->segs[R_FS].selector,
			    "gs", current_environment->segs[R_GS].selector,
			    "eflags", current_environment->eflags,
			    "cr0", current_environment->cr[0],
			    //      "cr1", BX_CPU(0)->cr1, gone
			    "cr2", current_environment->cr[2],
			    "cr3", current_environment->cr[3],
			    "cr4", current_environment->cr[4],
			    "eip", current_environment->eip
			    );
	}
  Py_INCREF(Py_None);
  return retval;
}

static PyObject* PyFlxC_retranslate(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "retranslate");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *retval = Py_None;
  flx_bbl_flush();
  tb_flush(current_environment);
  return retval;
}

static PyObject* PyFlxC_disas_bbl(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "disas_bbl");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   uint32_t addr;
   PyObject *retval;

   if(!PyArg_ParseTuple(args, "I", &addr)) {
      // raise exception, too?
      return NULL;
   }
   flx_disassembly* disas = flx_disas_bbl(addr);
   retval = Py_BuildValue("s#", disas->s, disas->size);
   free(disas->s);
   free(disas);
   //Py_XINCREF(retval);
   if(retval == NULL){
      retval = Py_None;
   }
   return retval;

}

static PyObject* PyFlxC_eip(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "eip");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *retval = Py_None;
  if (current_environment)
    retval = Py_BuildValue("I", current_environment->eip);
  //Py_XINCREF(retval);

  return retval;
}

static PyObject* PyFlxC_filter_filtered(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "filter_filtered");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   uint32_t addr;
   PyObject *retval;

   if(!PyArg_ParseTuple(args, "I", &addr)) {
      // raise exception, too?
      return NULL;
   }
   retval = Py_BuildValue("I", flx_filter_search_by_addr(addr));
   //Py_XINCREF(retval);
   return retval;
}

static PyObject* PyFlxC_genreg(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "genreg");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   unsigned index;
   PyObject *retval;

   if (!current_environment) {
     Py_INCREF(Py_None);
     return Py_None;
   }

   if(!PyArg_ParseTuple(args, "I", &index)) {
      // raise exception, too?
      return NULL;
   }
   // BX_32BIT_REG_EDI is last register in the gen_reg array
   if(index > R_EDI) {
      return NULL;
   }

   retval = Py_BuildValue("I", current_environment->regs[index]);
   //Py_XINCREF(retval);
   return retval;
}


static PyObject* PyFlxC_creg(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "creg");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   unsigned index;
   PyObject *retval;

   if (!current_environment) {
     Py_INCREF(Py_None);
     return Py_None;
   }

   if(!PyArg_ParseTuple(args, "I", &index)) {
      // raise exception, too?
      return NULL;
   }
   
   retval = Py_BuildValue("I", current_environment->segs[index].base);
   //Py_XINCREF(retval);
   return retval;
}


static PyObject* PyFlxC_vmem_read(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_vmem_read");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
   uint32_t addr, len;
   PyObject *retval = Py_None;
   char *buf;

   if(!PyArg_ParseTuple(args, "II", &addr, &len)) {
      return NULL;
   }

   if (!current_environment) {
     Py_INCREF(Py_None);
     return Py_None;
   }

   buf = (char*)malloc(len);
   if (!buf)
     return PyErr_NoMemory();

   if (cpu_memory_rw_debug(current_environment,
			   addr,
			   (uint8_t*)buf,
			   len,
			   0) != 0){
     //fixme: set error message
     free(buf);
     //Py_INCREF(PyExc_RuntimeError);
     return PyErr_Format(PyExc_RuntimeError, 
			 "Error reading from 0x%08x (len: %d)\n",
			 addr,
			 len);
   }
   
   retval = Py_BuildValue("s#", buf, len);
   //Py_XINCREF(retval);
   free(buf);

   return retval;
}

static PyObject* PyFlxC_set_context(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_active");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  int pid;
  int tid;
  
  if(!PyArg_ParseTuple(args, "II", &pid, &tid)) {
    return NULL;
  }

  flx_context_set(pid,tid);
  
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* PyFlxC_set_instrumentation_active(PyObject *self, PyObject *args) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_active");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  int active_flag;
  
  if(!PyArg_ParseTuple(args, "I", &active_flag)) {
    return NULL;
  }
  
  flx_state.global_active = active_flag;
  
  Py_INCREF(Py_None);
  return Py_None;
}


static PyMethodDef PyFlxC_methods[] = {
    {"vmem_read", (PyCFunction)PyFlxC_vmem_read, METH_VARARGS,
     "Reads from virtual memory and returns a string"
    },
    {"registers", (PyCFunction)PyFlxC_registers, METH_VARARGS,
     "Returns a dictionary containing all registers"
    },
    {"breakpoint_insert", (PyCFunction)PyFlxC_breakpoint_insert, METH_VARARGS,
     "Insert breakpoint into current process"
    },
    {"breakpoint_delete", (PyCFunction)PyFlxC_breakpoint_delete, METH_VARARGS,
     "Delete breakpoint from current process"
    },
    {"eip", (PyCFunction)PyFlxC_eip, METH_VARARGS,
     "Returns the eip register"
    },
    {"retranslate", (PyCFunction)PyFlxC_retranslate, METH_VARARGS,
     "Retranslate all translation blocks"
    },
    {"disas_bbl", (PyCFunction)PyFlxC_disas_bbl, METH_VARARGS,
     "Disassemble a basic block beginning from addr"
    },
    {"genreg", (PyCFunction)PyFlxC_genreg, METH_VARARGS,
     "Returns a general purpose register"
    },
    {"filtered", (PyCFunction)PyFlxC_filter_filtered, METH_VARARGS,
     "Returns true if address is in filter range"
    },

    {"creg", (PyCFunction)PyFlxC_creg, METH_VARARGS,
     "Returns a control register"
    },
    {"arithwindow_enable", (PyCFunction)PyFlxC_arithwindow_enable, METH_VARARGS,
     "Start arithwindow opcode execution"
    },
    {"arithwindow_disable", (PyCFunction)PyFlxC_arithwindow_disable, METH_VARARGS,
     "Stop arithwindow opcode execution"
    },
    {"constsearch_enable", (PyCFunction)PyFlxC_constsearch_enable, METH_VARARGS,
     "Start constsearch"
    },
    {"constsearch_pattern", (PyCFunction)PyFlxC_constsearch_pattern, METH_VARARGS,
     "Add constsearch pattern"
    },
    {"constsearch_disable", (PyCFunction)PyFlxC_constsearch_disable, METH_VARARGS,
     "Stop constsearch"
    },
    {"constsearch_search", (PyCFunction)PyFlxC_constsearch_search, METH_VARARGS,
     "Search for patterns in memory"
    },
    {"functiontrace_enable", (PyCFunction)PyFlxC_functiontrace_enable, METH_VARARGS,
     "Enable function tracing"
    },
    {"functiontrace_disable", (PyCFunction)PyFlxC_functiontrace_disable, METH_VARARGS,
     "Disable function tracing"
    },
    {"functionentropy_disable", (PyCFunction)PyFlxC_functionentropy_disable, METH_VARARGS,
     "Stop functionentropy measurement"
    },
    {"functionentropy_enable", (PyCFunction)PyFlxC_functionentropy_enable, METH_VARARGS,
     "Start functionentropy measurement"
    },
    {"caballero_disable", (PyCFunction)PyFlxC_caballero_disable, METH_VARARGS,
     "Stop caballero opcode execution"
    },
    {"caballero_enable", (PyCFunction)PyFlxC_caballero_enable, METH_VARARGS,
     "Start caballero opcode execution"
    },
    {"bblwindow_get", (PyCFunction)PyFlxC_bblwindow_get, METH_VARARGS,
     "Get BBL by record index"
    },
    {"bblwindow_disable", (PyCFunction)PyFlxC_bblwindow_disable, METH_VARARGS,
     "Disable BBL recording"
    },
    {"bblwindow_enable", (PyCFunction)PyFlxC_bblwindow_enable, METH_VARARGS,
     "Enable BBL recording"
    },
    {"bbltrace_enable", (PyCFunction)PyFlxC_bbltrace_enable, METH_VARARGS,
     "Start bbltrace execution events"
    },
    {"bbltrace_disable", (PyCFunction)PyFlxC_bbltrace_disable, METH_VARARGS,
     "Stop bbltrace execution events"
    },
    {"filter_enable", (PyCFunction)PyFlxC_filter_enable, METH_VARARGS,
     "Activate translation filtering"
    },
    {"filter_add", (PyCFunction)PyFlxC_filter_add, METH_VARARGS,
     "Activate translation filtering"
    },
    {"filter_del", (PyCFunction)PyFlxC_filter_del, METH_VARARGS,
     "Activate translation filtering"
    },
    {"filter_disable", (PyCFunction)PyFlxC_filter_disable, METH_VARARGS,
     "Deactivate translation filtering"
    },
    {"memtrace_enable", (PyCFunction)PyFlxC_memtrace_enable, METH_VARARGS,
     "Start tracing memory access"
    },
    {"memtrace_disable", (PyCFunction)PyFlxC_memtrace_disable, METH_VARARGS,
     "Stop tracing memory access"
    },
    {"set_context", (PyCFunction)PyFlxC_set_context,
     METH_VARARGS, "Set instrumentation process/thread context"
    },
    {"set_instrumentation_active", (PyCFunction)PyFlxC_set_instrumentation_active,
     METH_VARARGS, "Set instrumentation active/inactive"
    },
    {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

PyMODINIT_FUNC initpyflxinstrument(void);
PyMODINIT_FUNC
initpyflxinstrument(void)
{

#ifdef DEBUG
  fprintf(stderr, "flxinstrument");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  printf("Starting up\n");
    // Py_InitModule3 takes 3 arguments. Other versions of this function are deprecated
  PyFlx_C_Module = Py_InitModule3("PyFlxInstrument", PyFlxC_methods,
                                       "Python QEMU instruments");
  Py_XINCREF(PyFlx_C_Module);

  PyFlx_REG_EAX = PyInt_FromLong(R_EAX);
  Py_XINCREF(PyFlx_REG_EAX);
  PyFlx_REG_ECX = PyInt_FromLong(R_ECX);
  Py_XINCREF(PyFlx_REG_ECX);
  PyFlx_REG_EDX = PyInt_FromLong(R_EDX);
  Py_XINCREF(PyFlx_REG_EDX);
  PyFlx_REG_EBX = PyInt_FromLong(R_EBX);
  Py_XINCREF(PyFlx_REG_EBX);
  PyFlx_REG_ESP = PyInt_FromLong(R_ESP);
  Py_XINCREF(PyFlx_REG_ESP);
  PyFlx_REG_EBP = PyInt_FromLong(R_EBP);
  Py_XINCREF(PyFlx_REG_EBP);
  PyFlx_REG_ESI = PyInt_FromLong(R_ESI);
  Py_XINCREF(PyFlx_REG_ESI);
  PyFlx_REG_EDI = PyInt_FromLong(R_EDI);
  Py_XINCREF(PyFlx_REG_EDI);
  PyFlx_ISEMPTY = PyInt_FromLong(FLX_SLOT_EMPTY);
  Py_XINCREF(PyFlx_ISEMPTY);
  PyFlx_ISCALL = PyInt_FromLong(FLX_SLOT_ISCALL);
  Py_XINCREF(PyFlx_ISCALL);
  PyFlx_ISJMP = PyInt_FromLong(FLX_SLOT_ISJMP);
  Py_XINCREF(PyFlx_ISJMP);

  PyObject_SetAttrString(PyFlx_C_Module, "REG_EAX", PyFlx_REG_EAX );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_ECX", PyFlx_REG_ECX );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_EDX", PyFlx_REG_EDX );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_EBX", PyFlx_REG_EBX );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_ESP", PyFlx_REG_ESP );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_EBP", PyFlx_REG_EBP );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_ESI", PyFlx_REG_ESI );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_EDI", PyFlx_REG_EDI );
  PyObject_SetAttrString(PyFlx_C_Module, "SLOT_EMPTY", PyFlx_ISEMPTY );
  PyObject_SetAttrString(PyFlx_C_Module, "SLOT_CALL", PyFlx_ISCALL );
  PyObject_SetAttrString(PyFlx_C_Module, "SLOT_JMP", PyFlx_ISJMP );
}


static void
flxinstrument_state_init(void){
   memset(&flx_state, 0, sizeof(flx_state));
   char* ptr = getenv("FLX_DISABLE");
   if(ptr)
	flx_state.python_active = 0;
   else{
	flx_state.ret_active = 0;
	flx_state.call_active = 1;
	flx_state.python_active = 1;
	flx_state.syscall_active = 1;
   }

}

static void
flxinstrument_register_callbacks(void){
   printf("Python instrumentation registering callbacks ... ");
   PyFlx_ev_call = PyObject_GetAttrString(Py_Python_Module, "ev_call");
   Py_XINCREF(PyFlx_ev_call);
   PyFlx_ev_memtrace = PyObject_GetAttrString(Py_Python_Module, "ev_memtrace");
   Py_XINCREF(PyFlx_ev_memtrace);
   PyFlx_ev_caballero = PyObject_GetAttrString(Py_Python_Module, "ev_caballero");
   Py_XINCREF(PyFlx_ev_caballero);
   PyFlx_ev_arithwindow = PyObject_GetAttrString(Py_Python_Module, "ev_arithwindow");
   Py_XINCREF(PyFlx_ev_arithwindow);
   PyFlx_ev_functiontrace = PyObject_GetAttrString(Py_Python_Module, "ev_functiontrace");
   Py_XINCREF(PyFlx_ev_functiontrace);
   PyFlx_ev_functionentropy = PyObject_GetAttrString(Py_Python_Module, "ev_functionentropy");
   Py_XINCREF(PyFlx_ev_functionentropy);
   PyFlx_ev_constsearch = PyObject_GetAttrString(Py_Python_Module, "ev_constsearch");
   Py_XINCREF(PyFlx_ev_constsearch);
   PyFlx_ev_jmp = PyObject_GetAttrString(Py_Python_Module, "ev_jmp");
   Py_XINCREF(PyFlx_ev_jmp);
   PyFlx_ev_ret = PyObject_GetAttrString(Py_Python_Module, "ev_ret");
   Py_XINCREF(PyFlx_ev_ret);
   PyFlx_ev_bp = PyObject_GetAttrString(Py_Python_Module, "ev_bp");
   Py_XINCREF(PyFlx_ev_bp);
   PyFlx_ev_syscall = PyObject_GetAttrString(Py_Python_Module, "ev_syscall");
   Py_XINCREF(PyFlx_ev_syscall);
   PyFlx_ev_update_cr3 = PyObject_GetAttrString(Py_Python_Module, "ev_update_cr3");
   Py_XINCREF(PyFlx_ev_update_cr3);   
   PyFlx_ev_bblstart = PyObject_GetAttrString(Py_Python_Module, "ev_bblstart");
   Py_XINCREF(PyFlx_ev_bblstart);
   PyFlx_ev_shutdown = PyObject_GetAttrString(Py_Python_Module, "ev_shutdown");
   Py_XINCREF(PyFlx_ev_shutdown);
   printf("done!\n");
}


/* we dont need that yet 
static void
flxinstrument_unregister_callbacks(void){
     printf("Python instrumentation unregistering callbacks ... ");
     flx_state.python_active = 0;
     Py_XDECREF(PyFlx_ev_update_cr3);
     PyFlx_ev_update_cr3 = NULL;
     Py_XDECREF(PyFlx_ev_call);
     PyFlx_ev_call = NULL;
     Py_XDECREF(PyFlx_ev_memtrace);
     PyFlx_ev_memtrace = NULL;
     Py_XDECREF(PyFlx_ev_jmp);
     PyFlx_ev_jmp = NULL;
     Py_XDECREF(PyFlx_ev_ret);
     PyFlx_ev_ret = NULL;
     Py_XDECREF(PyFlx_ev_bp);
     PyFlx_ev_bp = NULL;
     Py_XDECREF(PyFlx_ev_syscall);
     PyFlx_ev_syscall = NULL;
     printf("done!\n");
}*/

void flxinstrument_init(void) { 
  PyObject* enable_python;

   printf("initializing flxinstrument\n");
   Py_Initialize();
   initpyflxinstrument();

   Py_Python_Module = PyImport_ImportModule("PyQEMU");
   
   if (!Py_Python_Module) {
     PyErr_Print();
     exit(1);
   }

   printf("foobar1\n");
   flxinstrument_state_init();

   Py_XINCREF(Py_Python_Module);
   
   enable_python = PyObject_CallMethod(Py_Python_Module, (char*)"init", (char*)"I",0);
   printf("foobar2\n");
   if(PyErr_Occurred()){
		printf("PyQEMU exception occured while initializing!\n");
		printf("TERMINATING\n");
		exit(-1);
   }
   if (PyInt_Check(enable_python) && (PyInt_AS_LONG(enable_python) != 1)){
   	  printf("foobar4\n");
      flxinstrument_register_callbacks();
   }
   else{
      printf("PyQEMU init method did not return 0 or was not callable, disabling!!!\n");
      flx_state.python_active = 0;
      return;
   }

   printf("foobar3\n");
   // initialize subsystems
   printf("initializing flxinstrument subsystems\n");
   flx_context_init();
   flx_filter_init();
   flx_bbl_init();
   flx_breakpoint_init();
   flx_bbltrace_init();
   flx_bbltranslate_init();
   flx_memtrace_init();
   flx_calltrace_init();
   flx_bblwindow_init();

   // low level callbacks
   //flx_bbltrace_register_handler((bbltrace_handler)flxinstrument_bbltrace_event);
   //flx_memtrace_register_handler((memtrace_handler)flxinstrument_memtrace_event);
   //flx_functiontrace_init((functiontrace_handler)flxinstrument_functiontrace_event);

   // high level callbacks
   flx_caballero_init((caballero_handler)flxinstrument_caballero_event);
   flx_arithwindow_init((arithwindow_handler)flxinstrument_arithwindow_event);
   flx_functionentropy_init((functionentropy_handler)flxinstrument_functionentropy_event);
   flx_constsearch_init((constsearch_handler)flxinstrument_constsearch_event);
   printf("initializing flxinstrument subsystems done\n");
   printf("initializing flxinstrument done\n");
}


/* ---------------------------- Instrument stuff ----------------- */


int flxinstrument_update_cr3(uint32_t old_cr3, uint32_t new_cr3) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_update_cr3");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif

  //static uint8_t last_monitored = 0;
  PyObject *result;
  int retval = 0;
  
  
  if (!PyCallable_Check(PyFlx_ev_update_cr3)) {
    fprintf(stderr, "Not callable\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_update_cr3, 
				 (char*)"(II)", 
				 old_cr3, 
				 new_cr3);
#ifdef DEBUG
  fprintf(stderr, "ev_update_cr3 returned!\n");
#endif

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);

  }
  else {
    PyErr_Print();
  }

  return retval;
}

int flxinstrument_syscall_event(uint32_t eax) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_syscall_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_syscall)) {
    fprintf(stderr, "No registered syscall event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_syscall,
				 (char*) "(I)",
				 eax);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_shutdown_event(void) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_shutdown_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_shutdown)) {
    fprintf(stderr, "No registered memtrace event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_shutdown,
				 (char*) "()" );

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_bbltrace_event(uint32_t eip, uint32_t esp) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_bblstart_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_bblstart)) {
    fprintf(stderr, "No registered memtrace event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_bblstart,
				 (char*) "(II)",
				 eip,
				 esp);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_constsearch_event(uint32_t eip, uint8_t* pattern, uint32_t len) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_constsearch_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_constsearch)) {
    fprintf(stderr, "No registered constsearch event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_constsearch,
				 (char*) "(s#I)",
				 pattern,
				 len,
				 eip);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  return retval;
}

int flxinstrument_functionentropy_event(float entropychange, uint32_t start) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_functionentropy_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_functionentropy)) {
    fprintf(stderr, "No registered functionentropy event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_functionentropy,
				 (char*) "(If)",
				 start,
				 entropychange);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_functiontrace_event(uint32_t eip, uint8_t type) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_functiontrace_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_functiontrace)) {
    fprintf(stderr, "No registered functiontrace event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_functiontrace,
				 (char*) "(II)",
				 eip,
				 type);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_arithwindow_event(uint32_t eip) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_arithwindow_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_arithwindow)) {
    fprintf(stderr, "No registered arithwindow event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_arithwindow,
				 (char*) "(I)",
				 eip);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_caballero_event(uint32_t eip, uint32_t icount, uint32_t arithcount) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_caballero_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_caballero)) {
    fprintf(stderr, "No registered caballero event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_caballero,
				 (char*) "(III)",
				 eip,
				 icount,
				 arithcount);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_memtrace_event(uint32_t address, uint32_t value, uint8_t size, uint8_t iswrite) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_memtrace_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_memtrace)) {
    fprintf(stderr, "No registered memtrace event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_memtrace,
				 (char*) "(IIII)",
				 address,
				 value,
				 size,
				 iswrite);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_call_event(uint32_t call_origin, uint32_t call_destination, uint32_t next_eip, uint32_t esp) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_call_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_call)) {
    fprintf(stderr, "No registered call event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_call,
				 (char*) "(IIII)",
				 call_origin,
				 call_destination,
				 next_eip,
                                 esp);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_jmp_event(uint32_t jmp_source, uint32_t jmp_destination) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_jmp_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_jmp)) {
    fprintf(stderr, "No registered call event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_jmp,
				 (char*) "(II)",
				 jmp_source,
				 jmp_destination);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_breakpoint_event(uint32_t eip) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_breakpoint_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_bp)) {
    fprintf(stderr, "No registered ret event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_bp,
				 (char*) "(I)",
				 eip);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

int flxinstrument_ret_event(uint32_t eip, uint32_t new_eip) {
#ifdef DEBUG
  fprintf(stderr, "flxinstrument_ret_event");  
  if(PyErr_Occurred())
	fprintf(stderr," - EXCEPTION THROWN\n");
  else
	fprintf(stderr," - NO EXC\n");
#endif
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_ret)) {
    fprintf(stderr, "No registered ret event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_ret,
				 (char*) "(II)",
				 eip,
				 new_eip);

  if (result != Py_None) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

#ifdef DEBUG_SWITCHED_ON
#undef DEBUG
#undef DEBUG_SWITCHED_ON
#endif
