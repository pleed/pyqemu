#!/usr/bin/env python
# Copyright 2004-2008 Roman Yakovenko.
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# http://www.boost.org/LICENSE_1_0.txt)

import os
import sys

#find out the file location within the sources tree
this_module_dir_path = os.path.abspath ( os.path.dirname( sys.modules[__name__].__file__) )
#find out gccxml location
gccxml_09_path = os.path.join( this_module_dir_path, '..', '..', '..', 'gccxml_bin', 'v09', sys.platform, 'bin' )
#add pygccxml package to Python path
sys.path.append( os.path.join( this_module_dir_path, '..', '..' ) )


from pygccxml import parser
from pygccxml import declarations

#configure GCC-XML parser
config = parser.config_t( gccxml_path=gccxml_09_path)

#parsing source file
decls = parser.parse( ['test.h'], config )
global_ns = declarations.get_global_namespace( decls )

#you can select the class using "full" name
#t = global_ns.free_function_( '::foobar::bar' )
g = global_ns

import code
code.interact("foo",local=locals())
