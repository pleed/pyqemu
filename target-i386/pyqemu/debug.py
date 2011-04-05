
def debug_shell():
	traceback.print_exception(*sys.exc_info())
        import code
        code.interact("DBG",local = locals())
        sys.exit(-1)

