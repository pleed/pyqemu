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
#include "flx_instrument.h"


unsigned startup_time = 0;

#define dbg_cpu 0
// don't output debugging information from helper functions
#define dbg_printf


//#define vmem_read(env, addr, buf, len) cpu_memory_rw_debug(env, addr, buf, len, 0)
//#define pmem_read(addr,buf,len) cpu_physical_memory_rw(addr, buf, len, 0)


#define LOG_THIS

// Most of this code was ripped from bochs and slightly modified to make it a little "cleaner"



// #define PROFILE_PYTHON
int python_active;
int instrumentation_active;
int instrumentation_call_active;

static PyObject *Py_Python_Module;
static PyObject *PyFlx_C_Module;

//todo: register and unregister routines
PyObject *PyFlx_ev_call = NULL;
PyObject *PyFlx_ev_update_cr3 = NULL;

static PyObject *PyFlx_REG_EAX;
static PyObject *PyFlx_REG_ECX;
static PyObject *PyFlx_REG_EDX;
static PyObject *PyFlx_REG_EBX;
static PyObject *PyFlx_REG_ESP;
static PyObject *PyFlx_REG_EBP;
static PyObject *PyFlx_REG_ESI;
static PyObject *PyFlx_REG_EDI;


CPUState *current_environment = NULL;


static PyObject* PyFlxC_registers(PyObject *self, PyObject *args) {
   PyObject *retval = NULL;
   if(!PyArg_ParseTuple(args, "")) {
      // raise exception, too?
      return NULL;
   }

   if (current_environment)
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
   else
     retval = NULL; //Py_None;
   
   Py_XINCREF(retval);
   return retval;
}


static PyObject* PyFlxC_eip(PyObject *self, PyObject *args) {
  PyObject *retval = Py_None;
  if (current_environment)
    retval = Py_BuildValue("I", current_environment->eip);
  Py_XINCREF(retval);

  return retval;
}



static PyObject* PyFlxC_genreg(PyObject *self, PyObject *args) {
   unsigned index;
   PyObject *retval;

   if (!current_environment) {
     Py_XINCREF(Py_None);
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
   Py_XINCREF(retval);
   return retval;
}


static PyObject* PyFlxC_creg(PyObject *self, PyObject *args) {
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
   Py_XINCREF(retval);
   return retval;
}


static PyObject* PyFlxC_vmem_read(PyObject *self, PyObject *args) {
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
     Py_INCREF(PyExc_RuntimeError);
     return PyErr_Format(PyExc_RuntimeError, 
			 "Error reading from 0x%08x (len: %d)\n",
			 addr,
			 len);
   }
   
   retval = Py_BuildValue("s#", buf, len);
   Py_XINCREF(retval);
   free(buf);

   return retval;
}


static PyObject* PyFlxC_set_instrumentation_active(PyObject *self, PyObject *args) {
  int active_flag;
  
  if(!PyArg_ParseTuple(args, "I", &active_flag)) {
    return NULL;
  }
  
  instrumentation_active = active_flag;
  
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
    {"eip", (PyCFunction)PyFlxC_eip, METH_VARARGS,
     "Returns the eip register"
    },
    {"genreg", (PyCFunction)PyFlxC_genreg, METH_VARARGS,
     "Returns a general purpose register"
    },
    {"creg", (PyCFunction)PyFlxC_creg, METH_VARARGS,
     "Returns a control register"
    },
    {"set_instrumentation_active", (PyCFunction)PyFlxC_set_instrumentation_active,
     METH_VARARGS, "Set instrumentation active/inactive"},
    {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

PyMODINIT_FUNC initpyflxinstrument(void);
//void flxinstrument_init(void);


PyMODINIT_FUNC
initpyflxinstrument(void)
{

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

  PyObject_SetAttrString(PyFlx_C_Module, "REG_EAX", PyFlx_REG_EAX );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_ECX", PyFlx_REG_ECX );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_EDX", PyFlx_REG_EDX );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_EBX", PyFlx_REG_EBX );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_ESP", PyFlx_REG_ESP );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_EBP", PyFlx_REG_EBP );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_ESI", PyFlx_REG_ESI );
  PyObject_SetAttrString(PyFlx_C_Module, "REG_EDI", PyFlx_REG_EDI );
}



void flxinstrument_init(void) { 

  PyObject* enable_python;

  printf("initialize\n");
   Py_Initialize();
   initpyflxinstrument();

   Py_Python_Module = PyImport_ImportModule("PyQEMU");
   
   if (!Py_Python_Module) {
     PyErr_Print();
     exit(1);
   }

   Py_XINCREF(Py_Python_Module);

   instrumentation_active = 0;
   instrumentation_call_active = 0;
   
   PyFlx_ev_call = PyObject_GetAttrString(Py_Python_Module, "ev_call");
   Py_XINCREF(PyFlx_ev_call);
   if (PyFlx_ev_call && PyCallable_Check(PyFlx_ev_call))
     {
       printf("Call event active\n");
       instrumentation_call_active = 1;
     }   
   

   PyFlx_ev_update_cr3 = PyObject_GetAttrString(Py_Python_Module, "ev_update_cr3");
   Py_XINCREF(PyFlx_ev_update_cr3);   

   enable_python = PyObject_CallMethod(Py_Python_Module, (char*)"init", (char*)"I",0);
   if (!PyInt_Check(enable_python) || (PyInt_AS_LONG(enable_python) == 0)) {
     printf("Python instrumentation disabled. Init returned None or 0\n");
     instrumentation_call_active = 0;
     instrumentation_active = 0;
     python_active = 0;

     Py_XDECREF(PyFlx_ev_update_cr3);
     PyFlx_ev_update_cr3 = NULL;

     Py_XDECREF(PyFlx_ev_call);
     PyFlx_ev_call = NULL;
     
   }
}


/* ---------------------------- Instrument stuff ----------------- */


int flxinstrument_update_cr3(uint32_t old_cr3, uint32_t new_cr3) {
  
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

  if (result) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }

  return retval;
}


int flxinstrument_call_event(uint32_t call_origin, uint32_t call_destination) {
  PyObject *result;
  int retval = 0;

  if (!PyCallable_Check(PyFlx_ev_call)) {
    fprintf(stderr, "No registered call event handler\n");
    return retval;
  }

  result = PyObject_CallFunction(PyFlx_ev_call,
				 (char*) "(II)",
				 call_origin,
				 call_destination);

  if (result) {
    retval = PyInt_AsLong(result);
    Py_XDECREF(result);
  }
  else {
    PyErr_Print();
  }
  
  return retval;
}

