	;; this is a test to see if the xed resync mechanism works
	;; when it encounters function symbols.
	
	[bits 64]

	SECTION .text
	global foo:function
foo:
	ret
	db 0x00
	global bar:function
bar:
	db 0x00, 0x00
	ret
	
	SECTION .text1
	global foo1:function
foo1:
	ret
	global bar1:function
bar1:
	db 0x00, 0x00
	ret
	
