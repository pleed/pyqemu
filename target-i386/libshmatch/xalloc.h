/**

  @file
  
  @brief Kernelspace/userspace boundary breaking headerfile.
    
  Part of Georgios Portokalidis' Aho Corasick algorithm.
  
  FIXME: the same functionality is delivered by support/spaces.h
  remove this file and all references to it.
  
  ----
  
  Fairly Fast Packet Filter
  http://ffpf.sourceforge.net/

  Copyright (c), 2003 - 2004 Georgios Portokalidis, Herbert Bos & Willem de Bruijn
  contact info : wdebruij_AT_users.sourceforge.net

  ----
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#ifndef XALLOC_H
#define XALLOC_H


#ifdef __KERNEL__
#include <linux/slab.h>
#define xalloc(s) kmalloc(s,GFP_KERNEL)
#define xfree(s) kfree(s)
#else
#ifdef USE_PYTHON_MALLOC
#include <Python.h>
#define xalloc(s) PyMem_Malloc(s)
#define xfree(s) PyMem_Free(s)
#else
#include <stdlib.h>
#define xalloc(s) malloc(s)
#define xfree(s) free(s)
#endif
#endif


#endif
