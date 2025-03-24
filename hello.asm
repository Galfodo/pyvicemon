

	* = $0801
	.byte $0b,$08,$00,$00,$9e,$32,$30,$36,$31,$00,$00,$00
_start:
	lda #<txt
	ldy #>txt
	jmp $ab1e
txt:
	.text "HELLO, WORLD!",0
