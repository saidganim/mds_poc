
a.out:     file format elf64-x86-64


Disassembly of section .interp:

00000000004002a8 <.interp>:
  4002a8:	2f                   	(bad)  
  4002a9:	6c                   	insb   (%dx),%es:(%rdi)
  4002aa:	69 62 36 34 2f 6c 64 	imul   $0x646c2f34,0x36(%rdx),%esp
  4002b1:	2d 6c 69 6e 75       	sub    $0x756e696c,%eax
  4002b6:	78 2d                	js     4002e5 <_init-0xd1b>
  4002b8:	78 38                	js     4002f2 <_init-0xd0e>
  4002ba:	36 2d 36 34 2e 73    	ss sub $0x732e3436,%eax
  4002c0:	6f                   	outsl  %ds:(%rsi),(%dx)
  4002c1:	2e 32 00             	xor    %cs:(%rax),%al

Disassembly of section .note.gnu.build-id:

00000000004002c4 <.note.gnu.build-id>:
  4002c4:	04 00                	add    $0x0,%al
  4002c6:	00 00                	add    %al,(%rax)
  4002c8:	14 00                	adc    $0x0,%al
  4002ca:	00 00                	add    %al,(%rax)
  4002cc:	03 00                	add    (%rax),%eax
  4002ce:	00 00                	add    %al,(%rax)
  4002d0:	47                   	rex.RXB
  4002d1:	4e 55                	rex.WRX push %rbp
  4002d3:	00 84 76 9d 05 d3 b1 	add    %al,-0x4e2cfa63(%rsi,%rsi,2)
  4002da:	21 c0                	and    %eax,%eax
  4002dc:	b2 d0                	mov    $0xd0,%dl
  4002de:	d7                   	xlat   %ds:(%rbx)
  4002df:	d3 85 f5 7c a8 98    	roll   %cl,-0x6757830b(%rbp)
  4002e5:	c1                   	.byte 0xc1
  4002e6:	24 30                	and    $0x30,%al

Disassembly of section .note.ABI-tag:

00000000004002e8 <.note.ABI-tag>:
  4002e8:	04 00                	add    $0x0,%al
  4002ea:	00 00                	add    %al,(%rax)
  4002ec:	10 00                	adc    %al,(%rax)
  4002ee:	00 00                	add    %al,(%rax)
  4002f0:	01 00                	add    %eax,(%rax)
  4002f2:	00 00                	add    %al,(%rax)
  4002f4:	47                   	rex.RXB
  4002f5:	4e 55                	rex.WRX push %rbp
  4002f7:	00 00                	add    %al,(%rax)
  4002f9:	00 00                	add    %al,(%rax)
  4002fb:	00 03                	add    %al,(%rbx)
  4002fd:	00 00                	add    %al,(%rax)
  4002ff:	00 02                	add    %al,(%rdx)
  400301:	00 00                	add    %al,(%rax)
  400303:	00 00                	add    %al,(%rax)
  400305:	00 00                	add    %al,(%rax)
	...

Disassembly of section .hash:

0000000000400308 <.hash>:
  400308:	03 00                	add    (%rax),%eax
  40030a:	00 00                	add    %al,(%rax)
  40030c:	0b 00                	or     (%rax),%eax
  40030e:	00 00                	add    %al,(%rax)
  400310:	0a 00                	or     (%rax),%al
  400312:	00 00                	add    %al,(%rax)
  400314:	05 00 00 00 09       	add    $0x9000000,%eax
	...
  400325:	00 00                	add    %al,(%rax)
  400327:	00 02                	add    %al,(%rdx)
  400329:	00 00                	add    %al,(%rax)
  40032b:	00 00                	add    %al,(%rax)
  40032d:	00 00                	add    %al,(%rax)
  40032f:	00 01                	add    %al,(%rcx)
  400331:	00 00                	add    %al,(%rax)
  400333:	00 04 00             	add    %al,(%rax,%rax,1)
  400336:	00 00                	add    %al,(%rax)
  400338:	06                   	(bad)  
  400339:	00 00                	add    %al,(%rax)
  40033b:	00 03                	add    %al,(%rbx)
  40033d:	00 00                	add    %al,(%rax)
  40033f:	00 08                	add    %cl,(%rax)
  400341:	00 00                	add    %al,(%rax)
  400343:	00 07                	add    %al,(%rdi)
  400345:	00 00                	add    %al,(%rax)
	...

Disassembly of section .gnu.hash:

0000000000400348 <.gnu.hash>:
  400348:	01 00                	add    %eax,(%rax)
  40034a:	00 00                	add    %al,(%rax)
  40034c:	01 00                	add    %eax,(%rax)
  40034e:	00 00                	add    %al,(%rax)
  400350:	01 00                	add    %eax,(%rax)
	...

Disassembly of section .dynsym:

0000000000400368 <.dynsym>:
	...
  400380:	01 00                	add    %eax,(%rax)
  400382:	00 00                	add    %al,(%rax)
  400384:	12 00                	adc    (%rax),%al
	...
  400396:	00 00                	add    %al,(%rax)
  400398:	27                   	(bad)  
  400399:	00 00                	add    %al,(%rax)
  40039b:	00 12                	add    %dl,(%rdx)
	...
  4003ad:	00 00                	add    %al,(%rax)
  4003af:	00 06                	add    %al,(%rsi)
  4003b1:	00 00                	add    %al,(%rax)
  4003b3:	00 12                	add    %dl,(%rdx)
	...
  4003c5:	00 00                	add    %al,(%rax)
  4003c7:	00 19                	add    %bl,(%rcx)
  4003c9:	00 00                	add    %al,(%rax)
  4003cb:	00 12                	add    %dl,(%rdx)
	...
  4003dd:	00 00                	add    %al,(%rax)
  4003df:	00 36                	add    %dh,(%rsi)
  4003e1:	00 00                	add    %al,(%rax)
  4003e3:	00 12                	add    %dl,(%rdx)
	...
  4003f5:	00 00                	add    %al,(%rax)
  4003f7:	00 0d 00 00 00 12    	add    %cl,0x12000000(%rip)        # 124003fd <_end+0x11ffa30d>
	...
  40040d:	00 00                	add    %al,(%rax)
  40040f:	00 66 00             	add    %ah,0x0(%rsi)
  400412:	00 00                	add    %al,(%rax)
  400414:	20 00                	and    %al,(%rax)
	...
  400426:	00 00                	add    %al,(%rax)
  400428:	20 00                	and    %al,(%rax)
  40042a:	00 00                	add    %al,(%rax)
  40042c:	12 00                	adc    (%rax),%al
	...
  40043e:	00 00                	add    %al,(%rax)
  400440:	31 00                	xor    %eax,(%rax)
  400442:	00 00                	add    %al,(%rax)
  400444:	12 00                	adc    (%rax),%al
	...
  400456:	00 00                	add    %al,(%rax)
  400458:	48 00 00             	rex.W add %al,(%rax)
  40045b:	00 12                	add    %dl,(%rdx)
	...

Disassembly of section .dynstr:

0000000000400470 <.dynstr>:
  400470:	00 70 75             	add    %dh,0x75(%rax)
  400473:	74 73                	je     4004e8 <_init-0xb18>
  400475:	00 70 72             	add    %dh,0x72(%rax)
  400478:	69 6e 74 66 00 73 69 	imul   $0x69730066,0x74(%rsi),%ebp
  40047f:	67 65 6d             	gs insl (%dx),%es:(%edi)
  400482:	70 74                	jo     4004f8 <_init-0xb08>
  400484:	79 73                	jns    4004f9 <_init-0xb07>
  400486:	65 74 00             	gs je  400489 <_init-0xb77>
  400489:	6d                   	insl   (%dx),%es:(%rdi)
  40048a:	65 6d                	gs insl (%dx),%es:(%rdi)
  40048c:	73 65                	jae    4004f3 <_init-0xb0d>
  40048e:	74 00                	je     400490 <_init-0xb70>
  400490:	6d                   	insl   (%dx),%es:(%rdi)
  400491:	61                   	(bad)  
  400492:	6c                   	insb   (%dx),%es:(%rdi)
  400493:	6c                   	insb   (%dx),%es:(%rdi)
  400494:	6f                   	outsl  %ds:(%rsi),(%dx)
  400495:	63 00                	movslq (%rax),%eax
  400497:	73 69                	jae    400502 <_init-0xafe>
  400499:	67 61                	addr32 (bad) 
  40049b:	63 74 69 6f          	movslq 0x6f(%rcx,%rbp,2),%esi
  40049f:	6e                   	outsb  %ds:(%rsi),(%dx)
  4004a0:	00 6f 70             	add    %ch,0x70(%rdi)
  4004a3:	65 6e                	outsb  %gs:(%rsi),(%dx)
  4004a5:	00 5f 5f             	add    %bl,0x5f(%rdi)
  4004a8:	6c                   	insb   (%dx),%es:(%rdi)
  4004a9:	69 62 63 5f 73 74 61 	imul   $0x6174735f,0x63(%rdx),%esp
  4004b0:	72 74                	jb     400526 <_init-0xada>
  4004b2:	5f                   	pop    %rdi
  4004b3:	6d                   	insl   (%dx),%es:(%rdi)
  4004b4:	61                   	(bad)  
  4004b5:	69 6e 00 73 79 73 63 	imul   $0x63737973,0x0(%rsi),%ebp
  4004bc:	6f                   	outsl  %ds:(%rsi),(%dx)
  4004bd:	6e                   	outsb  %ds:(%rsi),(%dx)
  4004be:	66 00 6c 69 62       	data16 add %ch,0x62(%rcx,%rbp,2)
  4004c3:	63 2e                	movslq (%rsi),%ebp
  4004c5:	73 6f                	jae    400536 <_init-0xaca>
  4004c7:	2e 36 00 47 4c       	cs add %al,%ss:0x4c(%rdi)
  4004cc:	49                   	rex.WB
  4004cd:	42                   	rex.X
  4004ce:	43 5f                	rex.XB pop %r15
  4004d0:	32 2e                	xor    (%rsi),%ch
  4004d2:	32 2e                	xor    (%rsi),%ch
  4004d4:	35 00 5f 5f 67       	xor    $0x675f5f00,%eax
  4004d9:	6d                   	insl   (%dx),%es:(%rdi)
  4004da:	6f                   	outsl  %ds:(%rsi),(%dx)
  4004db:	6e                   	outsb  %ds:(%rsi),(%dx)
  4004dc:	5f                   	pop    %rdi
  4004dd:	73 74                	jae    400553 <_init-0xaad>
  4004df:	61                   	(bad)  
  4004e0:	72 74                	jb     400556 <_init-0xaaa>
  4004e2:	5f                   	pop    %rdi
  4004e3:	5f                   	pop    %rdi
	...

Disassembly of section .gnu.version:

00000000004004e6 <.gnu.version>:
  4004e6:	00 00                	add    %al,(%rax)
  4004e8:	02 00                	add    (%rax),%al
  4004ea:	02 00                	add    (%rax),%al
  4004ec:	02 00                	add    (%rax),%al
  4004ee:	02 00                	add    (%rax),%al
  4004f0:	02 00                	add    (%rax),%al
  4004f2:	02 00                	add    (%rax),%al
  4004f4:	00 00                	add    %al,(%rax)
  4004f6:	02 00                	add    (%rax),%al
  4004f8:	02 00                	add    (%rax),%al
  4004fa:	02 00                	add    (%rax),%al

Disassembly of section .gnu.version_r:

0000000000400500 <.gnu.version_r>:
  400500:	01 00                	add    %eax,(%rax)
  400502:	01 00                	add    %eax,(%rax)
  400504:	50                   	push   %rax
  400505:	00 00                	add    %al,(%rax)
  400507:	00 10                	add    %dl,(%rax)
  400509:	00 00                	add    %al,(%rax)
  40050b:	00 00                	add    %al,(%rax)
  40050d:	00 00                	add    %al,(%rax)
  40050f:	00 75 1a             	add    %dh,0x1a(%rbp)
  400512:	69 09 00 00 02 00    	imul   $0x20000,(%rcx),%ecx
  400518:	5a                   	pop    %rdx
  400519:	00 00                	add    %al,(%rax)
  40051b:	00 00                	add    %al,(%rax)
  40051d:	00 00                	add    %al,(%rax)
	...

Disassembly of section .rela.dyn:

0000000000400520 <.rela.dyn>:
  400520:	f0 3f                	lock (bad) 
  400522:	40 00 00             	add    %al,(%rax)
  400525:	00 00                	add    %al,(%rax)
  400527:	00 06                	add    %al,(%rsi)
  400529:	00 00                	add    %al,(%rax)
  40052b:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 400531 <_init-0xacf>
  400531:	00 00                	add    %al,(%rax)
  400533:	00 00                	add    %al,(%rax)
  400535:	00 00                	add    %al,(%rax)
  400537:	00 f8                	add    %bh,%al
  400539:	3f                   	(bad)  
  40053a:	40 00 00             	add    %al,(%rax)
  40053d:	00 00                	add    %al,(%rax)
  40053f:	00 06                	add    %al,(%rsi)
  400541:	00 00                	add    %al,(%rax)
  400543:	00 07                	add    %al,(%rdi)
	...

Disassembly of section .rela.plt:

0000000000400550 <.rela.plt>:
  400550:	18 40 40             	sbb    %al,0x40(%rax)
  400553:	00 00                	add    %al,(%rax)
  400555:	00 00                	add    %al,(%rax)
  400557:	00 07                	add    %al,(%rdi)
  400559:	00 00                	add    %al,(%rax)
  40055b:	00 01                	add    %al,(%rcx)
	...
  400565:	00 00                	add    %al,(%rax)
  400567:	00 20                	add    %ah,(%rax)
  400569:	40                   	rex
  40056a:	40 00 00             	add    %al,(%rax)
  40056d:	00 00                	add    %al,(%rax)
  40056f:	00 07                	add    %al,(%rdi)
  400571:	00 00                	add    %al,(%rax)
  400573:	00 02                	add    %al,(%rdx)
	...
  40057d:	00 00                	add    %al,(%rax)
  40057f:	00 28                	add    %ch,(%rax)
  400581:	40                   	rex
  400582:	40 00 00             	add    %al,(%rax)
  400585:	00 00                	add    %al,(%rax)
  400587:	00 07                	add    %al,(%rdi)
  400589:	00 00                	add    %al,(%rax)
  40058b:	00 03                	add    %al,(%rbx)
	...
  400595:	00 00                	add    %al,(%rax)
  400597:	00 30                	add    %dh,(%rax)
  400599:	40                   	rex
  40059a:	40 00 00             	add    %al,(%rax)
  40059d:	00 00                	add    %al,(%rax)
  40059f:	00 07                	add    %al,(%rdi)
  4005a1:	00 00                	add    %al,(%rax)
  4005a3:	00 04 00             	add    %al,(%rax,%rax,1)
	...
  4005ae:	00 00                	add    %al,(%rax)
  4005b0:	38 40 40             	cmp    %al,0x40(%rax)
  4005b3:	00 00                	add    %al,(%rax)
  4005b5:	00 00                	add    %al,(%rax)
  4005b7:	00 07                	add    %al,(%rdi)
  4005b9:	00 00                	add    %al,(%rax)
  4005bb:	00 06                	add    %al,(%rsi)
	...
  4005c5:	00 00                	add    %al,(%rax)
  4005c7:	00 40 40             	add    %al,0x40(%rax)
  4005ca:	40 00 00             	add    %al,(%rax)
  4005cd:	00 00                	add    %al,(%rax)
  4005cf:	00 07                	add    %al,(%rdi)
  4005d1:	00 00                	add    %al,(%rax)
  4005d3:	00 08                	add    %cl,(%rax)
	...
  4005dd:	00 00                	add    %al,(%rax)
  4005df:	00 48 40             	add    %cl,0x40(%rax)
  4005e2:	40 00 00             	add    %al,(%rax)
  4005e5:	00 00                	add    %al,(%rax)
  4005e7:	00 07                	add    %al,(%rdi)
  4005e9:	00 00                	add    %al,(%rax)
  4005eb:	00 09                	add    %cl,(%rcx)
	...
  4005f5:	00 00                	add    %al,(%rax)
  4005f7:	00 50 40             	add    %dl,0x40(%rax)
  4005fa:	40 00 00             	add    %al,(%rax)
  4005fd:	00 00                	add    %al,(%rax)
  4005ff:	00 07                	add    %al,(%rdi)
  400601:	00 00                	add    %al,(%rax)
  400603:	00 0a                	add    %cl,(%rdx)
	...

Disassembly of section .init:

0000000000401000 <_init>:
  401000:	48 83 ec 08          	sub    $0x8,%rsp
  401004:	48 8b 05 ed 2f 00 00 	mov    0x2fed(%rip),%rax        # 403ff8 <__gmon_start__>
  40100b:	48 85 c0             	test   %rax,%rax
  40100e:	74 02                	je     401012 <_init+0x12>
  401010:	ff d0                	callq  *%rax
  401012:	48 83 c4 08          	add    $0x8,%rsp
  401016:	c3                   	retq   

Disassembly of section .plt:

0000000000401020 <.plt>:
  401020:	ff 35 e2 2f 00 00    	pushq  0x2fe2(%rip)        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
  401026:	ff 25 e4 2f 00 00    	jmpq   *0x2fe4(%rip)        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
  40102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401030 <puts@plt>:
  401030:	ff 25 e2 2f 00 00    	jmpq   *0x2fe2(%rip)        # 404018 <puts@GLIBC_2.2.5>
  401036:	68 00 00 00 00       	pushq  $0x0
  40103b:	e9 e0 ff ff ff       	jmpq   401020 <.plt>

0000000000401040 <sigaction@plt>:
  401040:	ff 25 da 2f 00 00    	jmpq   *0x2fda(%rip)        # 404020 <sigaction@GLIBC_2.2.5>
  401046:	68 01 00 00 00       	pushq  $0x1
  40104b:	e9 d0 ff ff ff       	jmpq   401020 <.plt>

0000000000401050 <printf@plt>:
  401050:	ff 25 d2 2f 00 00    	jmpq   *0x2fd2(%rip)        # 404028 <printf@GLIBC_2.2.5>
  401056:	68 02 00 00 00       	pushq  $0x2
  40105b:	e9 c0 ff ff ff       	jmpq   401020 <.plt>

0000000000401060 <memset@plt>:
  401060:	ff 25 ca 2f 00 00    	jmpq   *0x2fca(%rip)        # 404030 <memset@GLIBC_2.2.5>
  401066:	68 03 00 00 00       	pushq  $0x3
  40106b:	e9 b0 ff ff ff       	jmpq   401020 <.plt>

0000000000401070 <sigemptyset@plt>:
  401070:	ff 25 c2 2f 00 00    	jmpq   *0x2fc2(%rip)        # 404038 <sigemptyset@GLIBC_2.2.5>
  401076:	68 04 00 00 00       	pushq  $0x4
  40107b:	e9 a0 ff ff ff       	jmpq   401020 <.plt>

0000000000401080 <malloc@plt>:
  401080:	ff 25 ba 2f 00 00    	jmpq   *0x2fba(%rip)        # 404040 <malloc@GLIBC_2.2.5>
  401086:	68 05 00 00 00       	pushq  $0x5
  40108b:	e9 90 ff ff ff       	jmpq   401020 <.plt>

0000000000401090 <open@plt>:
  401090:	ff 25 b2 2f 00 00    	jmpq   *0x2fb2(%rip)        # 404048 <open@GLIBC_2.2.5>
  401096:	68 06 00 00 00       	pushq  $0x6
  40109b:	e9 80 ff ff ff       	jmpq   401020 <.plt>

00000000004010a0 <sysconf@plt>:
  4010a0:	ff 25 aa 2f 00 00    	jmpq   *0x2faa(%rip)        # 404050 <sysconf@GLIBC_2.2.5>
  4010a6:	68 07 00 00 00       	pushq  $0x7
  4010ab:	e9 70 ff ff ff       	jmpq   401020 <.plt>

Disassembly of section .text:

00000000004010b0 <_start>:
  4010b0:	31 ed                	xor    %ebp,%ebp
  4010b2:	49 89 d1             	mov    %rdx,%r9
  4010b5:	5e                   	pop    %rsi
  4010b6:	48 89 e2             	mov    %rsp,%rdx
  4010b9:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
  4010bd:	50                   	push   %rax
  4010be:	54                   	push   %rsp
  4010bf:	49 c7 c0 50 19 40 00 	mov    $0x401950,%r8
  4010c6:	48 c7 c1 f0 18 40 00 	mov    $0x4018f0,%rcx
  4010cd:	48 c7 c7 94 14 40 00 	mov    $0x401494,%rdi
  4010d4:	ff 15 16 2f 00 00    	callq  *0x2f16(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
  4010da:	f4                   	hlt    
  4010db:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)

00000000004010e0 <deregister_tm_clones>:
  4010e0:	b8 68 40 40 00       	mov    $0x404068,%eax
  4010e5:	48 3d 68 40 40 00    	cmp    $0x404068,%rax
  4010eb:	74 13                	je     401100 <deregister_tm_clones+0x20>
  4010ed:	b8 00 00 00 00       	mov    $0x0,%eax
  4010f2:	48 85 c0             	test   %rax,%rax
  4010f5:	74 09                	je     401100 <deregister_tm_clones+0x20>
  4010f7:	bf 68 40 40 00       	mov    $0x404068,%edi
  4010fc:	ff e0                	jmpq   *%rax
  4010fe:	66 90                	xchg   %ax,%ax
  401100:	c3                   	retq   
  401101:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
  401108:	00 00 00 00 
  40110c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401110 <register_tm_clones>:
  401110:	be 68 40 40 00       	mov    $0x404068,%esi
  401115:	48 81 ee 68 40 40 00 	sub    $0x404068,%rsi
  40111c:	48 89 f0             	mov    %rsi,%rax
  40111f:	48 c1 ee 3f          	shr    $0x3f,%rsi
  401123:	48 c1 f8 03          	sar    $0x3,%rax
  401127:	48 01 c6             	add    %rax,%rsi
  40112a:	48 d1 fe             	sar    %rsi
  40112d:	74 11                	je     401140 <register_tm_clones+0x30>
  40112f:	b8 00 00 00 00       	mov    $0x0,%eax
  401134:	48 85 c0             	test   %rax,%rax
  401137:	74 07                	je     401140 <register_tm_clones+0x30>
  401139:	bf 68 40 40 00       	mov    $0x404068,%edi
  40113e:	ff e0                	jmpq   *%rax
  401140:	c3                   	retq   
  401141:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
  401148:	00 00 00 00 
  40114c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401150 <__do_global_dtors_aux>:
  401150:	80 3d 29 2f 00 00 00 	cmpb   $0x0,0x2f29(%rip)        # 404080 <completed.0>
  401157:	75 17                	jne    401170 <__do_global_dtors_aux+0x20>
  401159:	55                   	push   %rbp
  40115a:	48 89 e5             	mov    %rsp,%rbp
  40115d:	e8 7e ff ff ff       	callq  4010e0 <deregister_tm_clones>
  401162:	c6 05 17 2f 00 00 01 	movb   $0x1,0x2f17(%rip)        # 404080 <completed.0>
  401169:	5d                   	pop    %rbp
  40116a:	c3                   	retq   
  40116b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
  401170:	c3                   	retq   
  401171:	66 66 2e 0f 1f 84 00 	data16 nopw %cs:0x0(%rax,%rax,1)
  401178:	00 00 00 00 
  40117c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000401180 <frame_dummy>:
  401180:	eb 8e                	jmp    401110 <register_tm_clones>

0000000000401182 <tlb_flush_all>:
  401182:	55                   	push   %rbp
  401183:	48 89 e5             	mov    %rsp,%rbp
  401186:	90                   	nop
  401187:	5d                   	pop    %rbp
  401188:	c3                   	retq   

0000000000401189 <evict_l1_cache>:
  401189:	55                   	push   %rbp
  40118a:	48 89 e5             	mov    %rsp,%rbp
  40118d:	48 89 7d e8          	mov    %rdi,-0x18(%rbp)
  401191:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401198:	eb 3e                	jmp    4011d8 <evict_l1_cache+0x4f>
  40119a:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40119d:	48 63 d0             	movslq %eax,%rdx
  4011a0:	48 8b 05 41 4f 00 00 	mov    0x4f41(%rip),%rax        # 4060e8 <mem>
  4011a7:	48 01 d0             	add    %rdx,%rax
  4011aa:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
  4011b0:	48 89 c2             	mov    %rax,%rdx
  4011b3:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  4011b7:	25 ff 0f 00 00       	and    $0xfff,%eax
  4011bc:	48 09 d0             	or     %rdx,%rax
  4011bf:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  4011c3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4011c7:	0f b6 00             	movzbl (%rax),%eax
  4011ca:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4011ce:	0f b6 00             	movzbl (%rax),%eax
  4011d1:	81 45 fc 00 10 00 00 	addl   $0x1000,-0x4(%rbp)
  4011d8:	8b 45 fc             	mov    -0x4(%rbp),%eax
  4011db:	48 63 d0             	movslq %eax,%rdx
  4011de:	48 8b 05 fb 4e 00 00 	mov    0x4efb(%rip),%rax        # 4060e0 <memsize>
  4011e5:	48 39 c2             	cmp    %rax,%rdx
  4011e8:	72 b0                	jb     40119a <evict_l1_cache+0x11>
  4011ea:	90                   	nop
  4011eb:	90                   	nop
  4011ec:	5d                   	pop    %rbp
  4011ed:	c3                   	retq   

00000000004011ee <clflush>:
  4011ee:	55                   	push   %rbp
  4011ef:	48 89 e5             	mov    %rsp,%rbp
  4011f2:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  4011f6:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4011fa:	0f ae 38             	clflush (%rax)
  4011fd:	90                   	nop
  4011fe:	5d                   	pop    %rbp
  4011ff:	c3                   	retq   

0000000000401200 <flush_all>:
  401200:	55                   	push   %rbp
  401201:	48 89 e5             	mov    %rsp,%rbp
  401204:	48 83 ec 10          	sub    $0x10,%rsp
  401208:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  40120f:	eb 29                	jmp    40123a <flush_all+0x3a>
  401211:	48 8b 15 88 2e 00 00 	mov    0x2e88(%rip),%rdx        # 4040a0 <oraclearr>
  401218:	8b 45 fc             	mov    -0x4(%rbp),%eax
  40121b:	c1 e0 10             	shl    $0x10,%eax
  40121e:	89 c1                	mov    %eax,%ecx
  401220:	8b 45 fc             	mov    -0x4(%rbp),%eax
  401223:	c1 e0 06             	shl    $0x6,%eax
  401226:	48 98                	cltq   
  401228:	48 01 c8             	add    %rcx,%rax
  40122b:	48 01 d0             	add    %rdx,%rax
  40122e:	48 89 c7             	mov    %rax,%rdi
  401231:	e8 b8 ff ff ff       	callq  4011ee <clflush>
  401236:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  40123a:	81 7d fc ff 00 00 00 	cmpl   $0xff,-0x4(%rbp)
  401241:	7e ce                	jle    401211 <flush_all+0x11>
  401243:	90                   	nop
  401244:	90                   	nop
  401245:	c9                   	leaveq 
  401246:	c3                   	retq   

0000000000401247 <void_operations3>:
  401247:	55                   	push   %rbp
  401248:	48 89 e5             	mov    %rsp,%rbp
  40124b:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  40124f:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  401253:	48 8b 15 56 2e 00 00 	mov    0x2e56(%rip),%rdx        # 4040b0 <addr1>
  40125a:	b8 10 00 00 00       	mov    $0x10,%eax
  40125f:	48 98                	cltq   
  401261:	48 01 d0             	add    %rdx,%rax
  401264:	c6 00 e1             	movb   $0xe1,(%rax)
  401267:	48 8b 15 32 2e 00 00 	mov    0x2e32(%rip),%rdx        # 4040a0 <oraclearr>
  40126e:	48 8b 0d 4b 2e 00 00 	mov    0x2e4b(%rip),%rcx        # 4040c0 <addr3>
  401275:	b8 10 00 00 00       	mov    $0x10,%eax
  40127a:	48 98                	cltq   
  40127c:	48 01 c8             	add    %rcx,%rax
  40127f:	0f b6 00             	movzbl (%rax),%eax
  401282:	0f b6 c0             	movzbl %al,%eax
  401285:	c1 e0 10             	shl    $0x10,%eax
  401288:	89 c0                	mov    %eax,%eax
  40128a:	48 01 d0             	add    %rdx,%rax
  40128d:	0f b6 00             	movzbl (%rax),%eax
  401290:	48 8b 15 09 2e 00 00 	mov    0x2e09(%rip),%rdx        # 4040a0 <oraclearr>
  401297:	48 8b 0d 22 2e 00 00 	mov    0x2e22(%rip),%rcx        # 4040c0 <addr3>
  40129e:	b8 10 00 00 00       	mov    $0x10,%eax
  4012a3:	48 98                	cltq   
  4012a5:	48 01 c8             	add    %rcx,%rax
  4012a8:	0f b6 00             	movzbl (%rax),%eax
  4012ab:	0f b6 c0             	movzbl %al,%eax
  4012ae:	c1 e0 10             	shl    $0x10,%eax
  4012b1:	89 c0                	mov    %eax,%eax
  4012b3:	48 01 d0             	add    %rdx,%rax
  4012b6:	0f b6 00             	movzbl (%rax),%eax
  4012b9:	48 8b 15 e0 2d 00 00 	mov    0x2de0(%rip),%rdx        # 4040a0 <oraclearr>
  4012c0:	48 8b 0d f1 2d 00 00 	mov    0x2df1(%rip),%rcx        # 4040b8 <addr2>
  4012c7:	b8 10 00 00 00       	mov    $0x10,%eax
  4012cc:	48 98                	cltq   
  4012ce:	48 01 c8             	add    %rcx,%rax
  4012d1:	0f b6 00             	movzbl (%rax),%eax
  4012d4:	0f b6 c0             	movzbl %al,%eax
  4012d7:	c1 e0 10             	shl    $0x10,%eax
  4012da:	89 c0                	mov    %eax,%eax
  4012dc:	48 01 d0             	add    %rdx,%rax
  4012df:	0f b6 00             	movzbl (%rax),%eax
  4012e2:	48 8b 15 b7 2d 00 00 	mov    0x2db7(%rip),%rdx        # 4040a0 <oraclearr>
  4012e9:	48 8b 0d c8 2d 00 00 	mov    0x2dc8(%rip),%rcx        # 4040b8 <addr2>
  4012f0:	b8 10 00 00 00       	mov    $0x10,%eax
  4012f5:	48 98                	cltq   
  4012f7:	48 01 c8             	add    %rcx,%rax
  4012fa:	0f b6 00             	movzbl (%rax),%eax
  4012fd:	0f b6 c0             	movzbl %al,%eax
  401300:	c1 e0 10             	shl    $0x10,%eax
  401303:	89 c0                	mov    %eax,%eax
  401305:	48 01 d0             	add    %rdx,%rax
  401308:	0f b6 00             	movzbl (%rax),%eax
  40130b:	90                   	nop
  40130c:	5d                   	pop    %rbp
  40130d:	c3                   	retq   

000000000040130e <void_operations2>:
  40130e:	55                   	push   %rbp
  40130f:	48 89 e5             	mov    %rsp,%rbp
  401312:	48 83 ec 10          	sub    $0x10,%rsp
  401316:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  40131a:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  40131e:	eb 18                	jmp    401338 <void_operations2+0x2a>
  401320:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401324:	48 8b 10             	mov    (%rax),%rdx
  401327:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40132b:	48 8b 00             	mov    (%rax),%rax
  40132e:	48 29 c2             	sub    %rax,%rdx
  401331:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401335:	48 89 10             	mov    %rdx,(%rax)
  401338:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40133c:	48 8b 10             	mov    (%rax),%rdx
  40133f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401343:	48 8b 00             	mov    (%rax),%rax
  401346:	48 39 c2             	cmp    %rax,%rdx
  401349:	7f d5                	jg     401320 <void_operations2+0x12>
  40134b:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40134f:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
  401353:	76 15                	jbe    40136a <void_operations2+0x5c>
  401355:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  401359:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  40135d:	48 89 d6             	mov    %rdx,%rsi
  401360:	48 89 c7             	mov    %rax,%rdi
  401363:	e8 1e 00 00 00       	callq  401386 <void_operations1>
  401368:	eb 1a                	jmp    401384 <void_operations2+0x76>
  40136a:	48 8b 15 47 2d 00 00 	mov    0x2d47(%rip),%rdx        # 4040b8 <addr2>
  401371:	48 8b 05 28 2d 00 00 	mov    0x2d28(%rip),%rax        # 4040a0 <oraclearr>
  401378:	48 89 d6             	mov    %rdx,%rsi
  40137b:	48 89 c7             	mov    %rax,%rdi
  40137e:	e8 c4 fe ff ff       	callq  401247 <void_operations3>
  401383:	90                   	nop
  401384:	c9                   	leaveq 
  401385:	c3                   	retq   

0000000000401386 <void_operations1>:
  401386:	55                   	push   %rbp
  401387:	48 89 e5             	mov    %rsp,%rbp
  40138a:	48 83 ec 10          	sub    $0x10,%rsp
  40138e:	48 89 7d f8          	mov    %rdi,-0x8(%rbp)
  401392:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
  401396:	eb 18                	jmp    4013b0 <void_operations1+0x2a>
  401398:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40139c:	48 8b 10             	mov    (%rax),%rdx
  40139f:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4013a3:	48 8b 00             	mov    (%rax),%rax
  4013a6:	48 29 c2             	sub    %rax,%rdx
  4013a9:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4013ad:	48 89 10             	mov    %rdx,(%rax)
  4013b0:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  4013b4:	48 8b 10             	mov    (%rax),%rdx
  4013b7:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4013bb:	48 8b 00             	mov    (%rax),%rax
  4013be:	48 39 c2             	cmp    %rax,%rdx
  4013c1:	7f d5                	jg     401398 <void_operations1+0x12>
  4013c3:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4013c7:	48 3b 45 f8          	cmp    -0x8(%rbp),%rax
  4013cb:	76 15                	jbe    4013e2 <void_operations1+0x5c>
  4013cd:	48 8b 55 f8          	mov    -0x8(%rbp),%rdx
  4013d1:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  4013d5:	48 89 d6             	mov    %rdx,%rsi
  4013d8:	48 89 c7             	mov    %rax,%rdi
  4013db:	e8 2e ff ff ff       	callq  40130e <void_operations2>
  4013e0:	eb 1a                	jmp    4013fc <void_operations1+0x76>
  4013e2:	48 8b 15 cf 2c 00 00 	mov    0x2ccf(%rip),%rdx        # 4040b8 <addr2>
  4013e9:	48 8b 05 b0 2c 00 00 	mov    0x2cb0(%rip),%rax        # 4040a0 <oraclearr>
  4013f0:	48 89 d6             	mov    %rdx,%rsi
  4013f3:	48 89 c7             	mov    %rax,%rdi
  4013f6:	e8 4c fe ff ff       	callq  401247 <void_operations3>
  4013fb:	90                   	nop
  4013fc:	c9                   	leaveq 
  4013fd:	c3                   	retq   

00000000004013fe <rdtscp>:
  4013fe:	55                   	push   %rbp
  4013ff:	48 89 e5             	mov    %rsp,%rbp
  401402:	0f 01 f9             	rdtscp 
  401405:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  401409:	48 89 55 f0          	mov    %rdx,-0x10(%rbp)
  40140d:	48 8b 45 f0          	mov    -0x10(%rbp),%rax
  401411:	48 c1 e0 20          	shl    $0x20,%rax
  401415:	48 09 45 f8          	or     %rax,-0x8(%rbp)
  401419:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40141d:	5d                   	pop    %rbp
  40141e:	c3                   	retq   

000000000040141f <time_access>:
  40141f:	55                   	push   %rbp
  401420:	48 89 e5             	mov    %rsp,%rbp
  401423:	48 83 ec 28          	sub    $0x28,%rsp
  401427:	48 89 7d d8          	mov    %rdi,-0x28(%rbp)
  40142b:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  40142f:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  401433:	b8 00 00 00 00       	mov    $0x0,%eax
  401438:	e8 c1 ff ff ff       	callq  4013fe <rdtscp>
  40143d:	48 89 45 f0          	mov    %rax,-0x10(%rbp)
  401441:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  401445:	0f b6 00             	movzbl (%rax),%eax
  401448:	b8 00 00 00 00       	mov    $0x0,%eax
  40144d:	e8 ac ff ff ff       	callq  4013fe <rdtscp>
  401452:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
  401456:	48 8b 45 e8          	mov    -0x18(%rbp),%rax
  40145a:	48 2b 45 f0          	sub    -0x10(%rbp),%rax
  40145e:	c9                   	leaveq 
  40145f:	c3                   	retq   

0000000000401460 <handler>:
  401460:	55                   	push   %rbp
  401461:	48 89 e5             	mov    %rsp,%rbp
  401464:	89 7d ec             	mov    %edi,-0x14(%rbp)
  401467:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
  40146b:	48 89 55 d8          	mov    %rdx,-0x28(%rbp)
  40146f:	48 8b 45 d8          	mov    -0x28(%rbp),%rax
  401473:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
  401477:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40147b:	48 8b 80 a8 00 00 00 	mov    0xa8(%rax),%rax
  401482:	48 8d 50 02          	lea    0x2(%rax),%rdx
  401486:	48 8b 45 f8          	mov    -0x8(%rbp),%rax
  40148a:	48 89 90 a8 00 00 00 	mov    %rdx,0xa8(%rax)
  401491:	90                   	nop
  401492:	5d                   	pop    %rbp
  401493:	c3                   	retq   

0000000000401494 <main>:
  401494:	55                   	push   %rbp
  401495:	48 89 e5             	mov    %rsp,%rbp
  401498:	48 81 ec 70 01 00 00 	sub    $0x170,%rsp
  40149f:	48 c7 45 b8 00 e1 f5 	movq   $0x5f5e100,-0x48(%rbp)
  4014a6:	05 
  4014a7:	48 c7 45 b0 64 00 00 	movq   $0x64,-0x50(%rbp)
  4014ae:	00 
  4014af:	48 c7 85 10 ff ff ff 	movq   $0x401460,-0xf0(%rbp)
  4014b6:	60 14 40 00 
  4014ba:	48 8d 85 10 ff ff ff 	lea    -0xf0(%rbp),%rax
  4014c1:	48 83 c0 08          	add    $0x8,%rax
  4014c5:	48 89 c7             	mov    %rax,%rdi
  4014c8:	e8 a3 fb ff ff       	callq  401070 <sigemptyset@plt>
  4014cd:	c7 45 98 00 00 00 10 	movl   $0x10000000,-0x68(%rbp)
  4014d4:	48 8d 85 10 ff ff ff 	lea    -0xf0(%rbp),%rax
  4014db:	ba 00 00 00 00       	mov    $0x0,%edx
  4014e0:	48 89 c6             	mov    %rax,%rsi
  4014e3:	bf 0b 00 00 00       	mov    $0xb,%edi
  4014e8:	e8 53 fb ff ff       	callq  401040 <sigaction@plt>
  4014ed:	83 f8 ff             	cmp    $0xffffffff,%eax
  4014f0:	75 0a                	jne    4014fc <main+0x68>
  4014f2:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
  4014f7:	e9 e4 03 00 00       	jmpq   4018e0 <main+0x44c>
  4014fc:	bf 00 00 14 00       	mov    $0x140000,%edi
  401501:	e8 7a fb ff ff       	callq  401080 <malloc@plt>
  401506:	48 05 00 10 00 00    	add    $0x1000,%rax
  40150c:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
  401512:	48 89 05 97 2b 00 00 	mov    %rax,0x2b97(%rip)        # 4040b0 <addr1>
  401519:	bf 00 00 14 00       	mov    $0x140000,%edi
  40151e:	e8 5d fb ff ff       	callq  401080 <malloc@plt>
  401523:	48 05 00 10 00 00    	add    $0x1000,%rax
  401529:	48 25 00 f0 ff ff    	and    $0xfffffffffffff000,%rax
  40152f:	48 89 05 8a 2b 00 00 	mov    %rax,0x2b8a(%rip)        # 4040c0 <addr3>
  401536:	48 b8 00 30 ac 6a 43 	movabs $0xffff9a436aac3000,%rax
  40153d:	9a ff ff 
  401540:	48 89 05 71 2b 00 00 	mov    %rax,0x2b71(%rip)        # 4040b8 <addr2>
  401547:	48 8b 15 6a 2b 00 00 	mov    0x2b6a(%rip),%rdx        # 4040b8 <addr2>
  40154e:	48 8b 05 5b 2b 00 00 	mov    0x2b5b(%rip),%rax        # 4040b0 <addr1>
  401555:	48 89 c6             	mov    %rax,%rsi
  401558:	bf 0c 20 40 00       	mov    $0x40200c,%edi
  40155d:	b8 00 00 00 00       	mov    $0x0,%eax
  401562:	e8 e9 fa ff ff       	callq  401050 <printf@plt>
  401567:	48 8b 15 42 2b 00 00 	mov    0x2b42(%rip),%rdx        # 4040b0 <addr1>
  40156e:	b8 10 00 00 00       	mov    $0x10,%eax
  401573:	48 98                	cltq   
  401575:	48 01 d0             	add    %rdx,%rax
  401578:	c6 00 e1             	movb   $0xe1,(%rax)
  40157b:	ba 00 00 00 00       	mov    $0x0,%edx
  401580:	be 00 00 00 00       	mov    $0x0,%esi
  401585:	bf 23 20 40 00       	mov    $0x402023,%edi
  40158a:	b8 00 00 00 00       	mov    $0x0,%eax
  40158f:	e8 fc fa ff ff       	callq  401090 <open@plt>
  401594:	89 05 2e 2b 00 00    	mov    %eax,0x2b2e(%rip)        # 4040c8 <tlb_fd>
  40159a:	bf 1e 00 00 00       	mov    $0x1e,%edi
  40159f:	e8 fc fa ff ff       	callq  4010a0 <sysconf@plt>
  4015a4:	48 c1 e0 0a          	shl    $0xa,%rax
  4015a8:	48 89 05 31 4b 00 00 	mov    %rax,0x4b31(%rip)        # 4060e0 <memsize>
  4015af:	48 8b 05 2a 4b 00 00 	mov    0x4b2a(%rip),%rax        # 4060e0 <memsize>
  4015b6:	48 89 c7             	mov    %rax,%rdi
  4015b9:	e8 c2 fa ff ff       	callq  401080 <malloc@plt>
  4015be:	48 89 05 23 4b 00 00 	mov    %rax,0x4b23(%rip)        # 4060e8 <mem>
  4015c5:	bf 00 00 00 01       	mov    $0x1000000,%edi
  4015ca:	e8 b1 fa ff ff       	callq  401080 <malloc@plt>
  4015cf:	48 89 05 ca 2a 00 00 	mov    %rax,0x2aca(%rip)        # 4040a0 <oraclearr>
  4015d6:	bf 04 00 00 00       	mov    $0x4,%edi
  4015db:	e8 a0 fa ff ff       	callq  401080 <malloc@plt>
  4015e0:	48 89 05 c1 2a 00 00 	mov    %rax,0x2ac1(%rip)        # 4040a8 <tmp_store>
  4015e7:	48 8b 15 d2 2a 00 00 	mov    0x2ad2(%rip),%rdx        # 4040c0 <addr3>
  4015ee:	b8 10 00 00 00       	mov    $0x10,%eax
  4015f3:	48 98                	cltq   
  4015f5:	48 01 d0             	add    %rdx,%rax
  4015f8:	c6 00 fa             	movb   $0xfa,(%rax)
  4015fb:	bf 38 20 40 00       	mov    $0x402038,%edi
  401600:	e8 2b fa ff ff       	callq  401030 <puts@plt>
  401605:	ba 00 08 00 00       	mov    $0x800,%edx
  40160a:	be 00 00 00 00       	mov    $0x0,%esi
  40160f:	bf e0 58 40 00       	mov    $0x4058e0,%edi
  401614:	e8 47 fa ff ff       	callq  401060 <memset@plt>
  401619:	ba 00 08 00 00       	mov    $0x800,%edx
  40161e:	be 00 00 00 00       	mov    $0x0,%esi
  401623:	bf e0 50 40 00       	mov    $0x4050e0,%edi
  401628:	e8 33 fa ff ff       	callq  401060 <memset@plt>
  40162d:	48 8b 05 6c 2a 00 00 	mov    0x2a6c(%rip),%rax        # 4040a0 <oraclearr>
  401634:	ba 00 00 00 01       	mov    $0x1000000,%edx
  401639:	be e3 00 00 00       	mov    $0xe3,%esi
  40163e:	48 89 c7             	mov    %rax,%rdi
  401641:	e8 1a fa ff ff       	callq  401060 <memset@plt>
  401646:	48 8b 15 63 2a 00 00 	mov    0x2a63(%rip),%rdx        # 4040b0 <addr1>
  40164d:	b8 10 00 00 00       	mov    $0x10,%eax
  401652:	48 98                	cltq   
  401654:	48 01 d0             	add    %rdx,%rax
  401657:	c6 00 fa             	movb   $0xfa,(%rax)
  40165a:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401661:	e9 59 01 00 00       	jmpq   4017bf <main+0x32b>
  401666:	ba 00 08 00 00       	mov    $0x800,%edx
  40166b:	be 00 00 00 00       	mov    $0x0,%esi
  401670:	bf e0 50 40 00       	mov    $0x4050e0,%edi
  401675:	e8 e6 f9 ff ff       	callq  401060 <memset@plt>
  40167a:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
  401681:	e9 95 00 00 00       	jmpq   40171b <main+0x287>
  401686:	c7 45 c0 00 00 00 00 	movl   $0x0,-0x40(%rbp)
  40168d:	c7 45 f4 00 00 00 00 	movl   $0x0,-0xc(%rbp)
  401694:	eb 19                	jmp    4016af <main+0x21b>
  401696:	48 8b 15 03 2a 00 00 	mov    0x2a03(%rip),%rdx        # 4040a0 <oraclearr>
  40169d:	8b 45 f4             	mov    -0xc(%rbp),%eax
  4016a0:	c1 e0 10             	shl    $0x10,%eax
  4016a3:	89 c0                	mov    %eax,%eax
  4016a5:	48 01 d0             	add    %rdx,%rax
  4016a8:	0f ae 38             	clflush (%rax)
  4016ab:	83 45 f4 01          	addl   $0x1,-0xc(%rbp)
  4016af:	81 7d f4 ff 00 00 00 	cmpl   $0xff,-0xc(%rbp)
  4016b6:	76 de                	jbe    401696 <main+0x202>
  4016b8:	48 8d 55 b0          	lea    -0x50(%rbp),%rdx
  4016bc:	48 8d 45 b8          	lea    -0x48(%rbp),%rax
  4016c0:	48 89 d6             	mov    %rdx,%rsi
  4016c3:	48 89 c7             	mov    %rax,%rdi
  4016c6:	e8 bb fc ff ff       	callq  401386 <void_operations1>
  4016cb:	c7 45 f0 00 00 00 00 	movl   $0x0,-0x10(%rbp)
  4016d2:	eb 3a                	jmp    40170e <main+0x27a>
  4016d4:	48 8b 15 c5 29 00 00 	mov    0x29c5(%rip),%rdx        # 4040a0 <oraclearr>
  4016db:	8b 45 f0             	mov    -0x10(%rbp),%eax
  4016de:	c1 e0 10             	shl    $0x10,%eax
  4016e1:	89 c0                	mov    %eax,%eax
  4016e3:	48 01 d0             	add    %rdx,%rax
  4016e6:	48 89 c7             	mov    %rax,%rdi
  4016e9:	e8 31 fd ff ff       	callq  40141f <time_access>
  4016ee:	48 89 c2             	mov    %rax,%rdx
  4016f1:	8b 45 f0             	mov    -0x10(%rbp),%eax
  4016f4:	48 8b 04 c5 e0 50 40 	mov    0x4050e0(,%rax,8),%rax
  4016fb:	00 
  4016fc:	48 01 c2             	add    %rax,%rdx
  4016ff:	8b 45 f0             	mov    -0x10(%rbp),%eax
  401702:	48 89 14 c5 e0 50 40 	mov    %rdx,0x4050e0(,%rax,8)
  401709:	00 
  40170a:	83 45 f0 01          	addl   $0x1,-0x10(%rbp)
  40170e:	81 7d f0 ff 00 00 00 	cmpl   $0xff,-0x10(%rbp)
  401715:	76 bd                	jbe    4016d4 <main+0x240>
  401717:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
  40171b:	83 7d f8 00          	cmpl   $0x0,-0x8(%rbp)
  40171f:	0f 8e 61 ff ff ff    	jle    401686 <main+0x1f2>
  401725:	48 c7 45 e8 ff ff ff 	movq   $0xffffffffffffffff,-0x18(%rbp)
  40172c:	ff 
  40172d:	c7 45 e4 ff ff ff ff 	movl   $0xffffffff,-0x1c(%rbp)
  401734:	c7 45 e0 00 00 00 00 	movl   $0x0,-0x20(%rbp)
  40173b:	eb 57                	jmp    401794 <main+0x300>
  40173d:	8b 45 e0             	mov    -0x20(%rbp),%eax
  401740:	48 98                	cltq   
  401742:	48 8b 04 c5 e0 50 40 	mov    0x4050e0(,%rax,8),%rax
  401749:	00 
  40174a:	48 8b 55 e8          	mov    -0x18(%rbp),%rdx
  40174e:	48 83 ea 01          	sub    $0x1,%rdx
  401752:	48 39 d0             	cmp    %rdx,%rax
  401755:	77 39                	ja     401790 <main+0x2fc>
  401757:	83 7d e0 00          	cmpl   $0x0,-0x20(%rbp)
  40175b:	74 33                	je     401790 <main+0x2fc>
  40175d:	48 8b 15 5c 29 00 00 	mov    0x295c(%rip),%rdx        # 4040c0 <addr3>
  401764:	b8 10 00 00 00       	mov    $0x10,%eax
  401769:	48 98                	cltq   
  40176b:	48 01 d0             	add    %rdx,%rax
  40176e:	0f b6 00             	movzbl (%rax),%eax
  401771:	0f b6 c0             	movzbl %al,%eax
  401774:	39 45 e0             	cmp    %eax,-0x20(%rbp)
  401777:	74 17                	je     401790 <main+0x2fc>
  401779:	8b 45 e0             	mov    -0x20(%rbp),%eax
  40177c:	48 98                	cltq   
  40177e:	48 8b 04 c5 e0 50 40 	mov    0x4050e0(,%rax,8),%rax
  401785:	00 
  401786:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
  40178a:	8b 45 e0             	mov    -0x20(%rbp),%eax
  40178d:	89 45 e4             	mov    %eax,-0x1c(%rbp)
  401790:	83 45 e0 01          	addl   $0x1,-0x20(%rbp)
  401794:	81 7d e0 ff 00 00 00 	cmpl   $0xff,-0x20(%rbp)
  40179b:	7e a0                	jle    40173d <main+0x2a9>
  40179d:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  4017a0:	48 98                	cltq   
  4017a2:	48 8b 04 c5 e0 58 40 	mov    0x4058e0(,%rax,8),%rax
  4017a9:	00 
  4017aa:	48 8d 50 01          	lea    0x1(%rax),%rdx
  4017ae:	8b 45 e4             	mov    -0x1c(%rbp),%eax
  4017b1:	48 98                	cltq   
  4017b3:	48 89 14 c5 e0 58 40 	mov    %rdx,0x4058e0(,%rax,8)
  4017ba:	00 
  4017bb:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  4017bf:	83 7d fc 13          	cmpl   $0x13,-0x4(%rbp)
  4017c3:	0f 8e 9d fe ff ff    	jle    401666 <main+0x1d2>
  4017c9:	48 c7 45 d0 ff ff ff 	movq   $0xffffffffffffffff,-0x30(%rbp)
  4017d0:	ff 
  4017d1:	b8 fe ff ff ff       	mov    $0xfffffffe,%eax
  4017d6:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
  4017da:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%rbp)
  4017e1:	e9 80 00 00 00       	jmpq   401866 <main+0x3d2>
  4017e6:	8b 45 c4             	mov    -0x3c(%rbp),%eax
  4017e9:	48 98                	cltq   
  4017eb:	48 8b 04 c5 e0 58 40 	mov    0x4058e0(,%rax,8),%rax
  4017f2:	00 
  4017f3:	48 39 45 d0          	cmp    %rax,-0x30(%rbp)
  4017f7:	7d 17                	jge    401810 <main+0x37c>
  4017f9:	8b 45 c4             	mov    -0x3c(%rbp),%eax
  4017fc:	48 98                	cltq   
  4017fe:	48 8b 04 c5 e0 58 40 	mov    0x4058e0(,%rax,8),%rax
  401805:	00 
  401806:	48 89 45 d0          	mov    %rax,-0x30(%rbp)
  40180a:	8b 45 c4             	mov    -0x3c(%rbp),%eax
  40180d:	89 45 dc             	mov    %eax,-0x24(%rbp)
  401810:	8b 45 c4             	mov    -0x3c(%rbp),%eax
  401813:	48 98                	cltq   
  401815:	48 8b 04 c5 e0 58 40 	mov    0x4058e0(,%rax,8),%rax
  40181c:	00 
  40181d:	48 39 45 c8          	cmp    %rax,-0x38(%rbp)
  401821:	7e 11                	jle    401834 <main+0x3a0>
  401823:	8b 45 c4             	mov    -0x3c(%rbp),%eax
  401826:	48 98                	cltq   
  401828:	48 8b 04 c5 e0 58 40 	mov    0x4058e0(,%rax,8),%rax
  40182f:	00 
  401830:	48 89 45 c8          	mov    %rax,-0x38(%rbp)
  401834:	8b 45 c4             	mov    -0x3c(%rbp),%eax
  401837:	48 98                	cltq   
  401839:	48 8b 0c c5 e0 50 40 	mov    0x4050e0(,%rax,8),%rcx
  401840:	00 
  401841:	8b 45 c4             	mov    -0x3c(%rbp),%eax
  401844:	48 98                	cltq   
  401846:	48 8b 14 c5 e0 58 40 	mov    0x4058e0(,%rax,8),%rdx
  40184d:	00 
  40184e:	8b 45 c4             	mov    -0x3c(%rbp),%eax
  401851:	89 c6                	mov    %eax,%esi
  401853:	bf 50 20 40 00       	mov    $0x402050,%edi
  401858:	b8 00 00 00 00       	mov    $0x0,%eax
  40185d:	e8 ee f7 ff ff       	callq  401050 <printf@plt>
  401862:	83 45 c4 01          	addl   $0x1,-0x3c(%rbp)
  401866:	81 7d c4 ff 00 00 00 	cmpl   $0xff,-0x3c(%rbp)
  40186d:	0f 8e 73 ff ff ff    	jle    4017e6 <main+0x352>
  401873:	48 8b 45 d0          	mov    -0x30(%rbp),%rax
  401877:	48 2b 45 c8          	sub    -0x38(%rbp),%rax
  40187b:	48 83 f8 05          	cmp    $0x5,%rax
  40187f:	7f 0f                	jg     401890 <main+0x3fc>
  401881:	bf 73 20 40 00       	mov    $0x402073,%edi
  401886:	e8 a5 f7 ff ff       	callq  401030 <puts@plt>
  40188b:	e9 6b fd ff ff       	jmpq   4015fb <main+0x167>
  401890:	48 8b 15 21 28 00 00 	mov    0x2821(%rip),%rdx        # 4040b8 <addr2>
  401897:	b8 10 00 00 00       	mov    $0x10,%eax
  40189c:	48 98                	cltq   
  40189e:	48 01 c2             	add    %rax,%rdx
  4018a1:	48 8b 0d 08 28 00 00 	mov    0x2808(%rip),%rcx        # 4040b0 <addr1>
  4018a8:	b8 10 00 00 00       	mov    $0x10,%eax
  4018ad:	48 98                	cltq   
  4018af:	48 01 c8             	add    %rcx,%rax
  4018b2:	48 89 c6             	mov    %rax,%rsi
  4018b5:	bf 8a 20 40 00       	mov    $0x40208a,%edi
  4018ba:	b8 00 00 00 00       	mov    $0x0,%eax
  4018bf:	e8 8c f7 ff ff       	callq  401050 <printf@plt>
  4018c4:	8b 55 dc             	mov    -0x24(%rbp),%edx
  4018c7:	8b 45 dc             	mov    -0x24(%rbp),%eax
  4018ca:	89 c6                	mov    %eax,%esi
  4018cc:	bf a6 20 40 00       	mov    $0x4020a6,%edi
  4018d1:	b8 00 00 00 00       	mov    $0x0,%eax
  4018d6:	e8 75 f7 ff ff       	callq  401050 <printf@plt>
  4018db:	b8 01 00 00 00       	mov    $0x1,%eax
  4018e0:	c9                   	leaveq 
  4018e1:	c3                   	retq   
  4018e2:	66 2e 0f 1f 84 00 00 	nopw   %cs:0x0(%rax,%rax,1)
  4018e9:	00 00 00 
  4018ec:	0f 1f 40 00          	nopl   0x0(%rax)

00000000004018f0 <__libc_csu_init>:
  4018f0:	41 57                	push   %r15
  4018f2:	4c 8d 3d 07 25 00 00 	lea    0x2507(%rip),%r15        # 403e00 <__frame_dummy_init_array_entry>
  4018f9:	41 56                	push   %r14
  4018fb:	49 89 d6             	mov    %rdx,%r14
  4018fe:	41 55                	push   %r13
  401900:	49 89 f5             	mov    %rsi,%r13
  401903:	41 54                	push   %r12
  401905:	41 89 fc             	mov    %edi,%r12d
  401908:	55                   	push   %rbp
  401909:	48 8d 2d f8 24 00 00 	lea    0x24f8(%rip),%rbp        # 403e08 <__do_global_dtors_aux_fini_array_entry>
  401910:	53                   	push   %rbx
  401911:	4c 29 fd             	sub    %r15,%rbp
  401914:	48 83 ec 08          	sub    $0x8,%rsp
  401918:	e8 e3 f6 ff ff       	callq  401000 <_init>
  40191d:	48 c1 fd 03          	sar    $0x3,%rbp
  401921:	74 1b                	je     40193e <__libc_csu_init+0x4e>
  401923:	31 db                	xor    %ebx,%ebx
  401925:	0f 1f 00             	nopl   (%rax)
  401928:	4c 89 f2             	mov    %r14,%rdx
  40192b:	4c 89 ee             	mov    %r13,%rsi
  40192e:	44 89 e7             	mov    %r12d,%edi
  401931:	41 ff 14 df          	callq  *(%r15,%rbx,8)
  401935:	48 83 c3 01          	add    $0x1,%rbx
  401939:	48 39 dd             	cmp    %rbx,%rbp
  40193c:	75 ea                	jne    401928 <__libc_csu_init+0x38>
  40193e:	48 83 c4 08          	add    $0x8,%rsp
  401942:	5b                   	pop    %rbx
  401943:	5d                   	pop    %rbp
  401944:	41 5c                	pop    %r12
  401946:	41 5d                	pop    %r13
  401948:	41 5e                	pop    %r14
  40194a:	41 5f                	pop    %r15
  40194c:	c3                   	retq   
  40194d:	0f 1f 00             	nopl   (%rax)

0000000000401950 <__libc_csu_fini>:
  401950:	c3                   	retq   

Disassembly of section .fini:

0000000000401954 <_fini>:
  401954:	48 83 ec 08          	sub    $0x8,%rsp
  401958:	48 83 c4 08          	add    $0x8,%rsp
  40195c:	c3                   	retq   

Disassembly of section .rodata:

0000000000402000 <_IO_stdin_used>:
  402000:	01 00                	add    %eax,(%rax)
  402002:	02 00                	add    (%rax),%al
  402004:	00 00                	add    %al,(%rax)
	...

0000000000402008 <offset>:
  402008:	10 00                	adc    %al,(%rax)
  40200a:	00 00                	add    %al,(%rax)
  40200c:	61                   	(bad)  
  40200d:	64 64 72 31          	fs fs jb 402042 <offset+0x3a>
  402011:	5b                   	pop    %rbx
  402012:	25 70 5d 20 3a       	and    $0x3a205d70,%eax
  402017:	20 61 64             	and    %ah,0x64(%rcx)
  40201a:	64 72 32             	fs jb  40204f <offset+0x47>
  40201d:	5b                   	pop    %rbx
  40201e:	25 70 5d 0a 00       	and    $0xa5d70,%eax
  402023:	2f                   	(bad)  
  402024:	64 65 76 2f          	fs gs jbe 402057 <offset+0x4f>
  402028:	74 6c                	je     402096 <offset+0x8e>
  40202a:	62                   	(bad)  
  40202b:	5f                   	pop    %rdi
  40202c:	69 6e 76 61 6c 69 64 	imul   $0x64696c61,0x76(%rsi),%ebp
  402033:	61                   	(bad)  
  402034:	74 6f                	je     4020a5 <offset+0x9d>
  402036:	72 00                	jb     402038 <offset+0x30>
  402038:	52                   	push   %rdx
  402039:	75 6e                	jne    4020a9 <offset+0xa1>
  40203b:	6e                   	outsb  %ds:(%rsi),(%dx)
  40203c:	69 6e 67 20 65 78 70 	imul   $0x70786520,0x67(%rsi),%ebp
  402043:	65 72 69             	gs jb  4020af <offset+0xa7>
  402046:	6d                   	insl   (%dx),%es:(%rdi)
  402047:	65 6e                	outsb  %gs:(%rsi),(%dx)
  402049:	74 73                	je     4020be <offset+0xb6>
  40204b:	00 00                	add    %al,(%rax)
  40204d:	00 00                	add    %al,(%rax)
  40204f:	00 42 59             	add    %al,0x59(%rdx)
  402052:	54                   	push   %rsp
  402053:	45 20 30             	and    %r14b,(%r8)
  402056:	78 25                	js     40207d <offset+0x75>
  402058:	30 32                	xor    %dh,(%rdx)
  40205a:	78 20                	js     40207c <offset+0x74>
  40205c:	3a 20                	cmp    (%rax),%ah
  40205e:	25 34 6c 75 20       	and    $0x20756c34,%eax
  402063:	77 69                	ja     4020ce <__GNU_EH_FRAME_HDR+0xe>
  402065:	6e                   	outsb  %ds:(%rsi),(%dx)
  402066:	73 20                	jae    402088 <offset+0x80>
  402068:	3a 20                	cmp    (%rax),%ah
  40206a:	25 34 6c 75 20       	and    $0x20756c34,%eax
  40206f:	75 73                	jne    4020e4 <__GNU_EH_FRAME_HDR+0x24>
  402071:	0a 00                	or     (%rax),%al
  402073:	4e 6f                	rex.WRX outsl %ds:(%rsi),(%dx)
  402075:	74 20                	je     402097 <offset+0x8f>
  402077:	65 67 6e             	outsb  %gs:(%esi),(%dx)
  40207a:	6f                   	outsl  %ds:(%rsi),(%dx)
  40207b:	75 67                	jne    4020e4 <__GNU_EH_FRAME_HDR+0x24>
  40207d:	68 20 63 6f 6e       	pushq  $0x6e6f6320
  402082:	66 69 64 65 6e 63 65 	imul   $0x6563,0x6e(%rbp,%riz,2),%sp
  402089:	00 41 44             	add    %al,0x44(%rcx)
  40208c:	52                   	push   %rdx
  40208d:	45 53                	rex.RB push %r11
  40208f:	53                   	push   %rbx
  402090:	45 53                	rex.RB push %r11
  402092:	20 57 45             	and    %dl,0x45(%rdi)
  402095:	52                   	push   %rdx
  402096:	45 20 5b 25          	and    %r11b,0x25(%r11)
  40209a:	70 5d                	jo     4020f9 <__GNU_EH_FRAME_HDR+0x39>
  40209c:	20 76 73             	and    %dh,0x73(%rsi)
  40209f:	20 5b 25             	and    %bl,0x25(%rbx)
  4020a2:	70 5d                	jo     402101 <__GNU_EH_FRAME_HDR+0x41>
  4020a4:	0a 00                	or     (%rax),%al
  4020a6:	57                   	push   %rdi
  4020a7:	69 6e 6e 65 72 20 69 	imul   $0x69207265,0x6e(%rsi),%ebp
  4020ae:	73 20                	jae    4020d0 <__GNU_EH_FRAME_HDR+0x10>
  4020b0:	30 78 25             	xor    %bh,0x25(%rax)
  4020b3:	30 32                	xor    %dh,(%rdx)
  4020b5:	78 20                	js     4020d7 <__GNU_EH_FRAME_HDR+0x17>
  4020b7:	5b                   	pop    %rbx
  4020b8:	25 63 5d 0a 00       	and    $0xa5d63,%eax

Disassembly of section .eh_frame_hdr:

00000000004020c0 <__GNU_EH_FRAME_HDR>:
  4020c0:	01 1b                	add    %ebx,(%rbx)
  4020c2:	03 3b                	add    (%rbx),%edi
  4020c4:	84 00                	test   %al,(%rax)
  4020c6:	00 00                	add    %al,(%rax)
  4020c8:	0f 00 00             	sldt   (%rax)
  4020cb:	00 60 ef             	add    %ah,-0x11(%rax)
  4020ce:	ff                   	(bad)  
  4020cf:	ff d0                	callq  *%rax
  4020d1:	00 00                	add    %al,(%rax)
  4020d3:	00 f0                	add    %dh,%al
  4020d5:	ef                   	out    %eax,(%dx)
  4020d6:	ff                   	(bad)  
  4020d7:	ff a0 00 00 00 c2    	jmpq   *-0x3e000000(%rax)
  4020dd:	f0 ff                	lock (bad) 
  4020df:	ff                   	(bad)  
  4020e0:	f8                   	clc    
  4020e1:	00 00                	add    %al,(%rax)
  4020e3:	00 c9                	add    %cl,%cl
  4020e5:	f0 ff                	lock (bad) 
  4020e7:	ff 18                	lcall  *(%rax)
  4020e9:	01 00                	add    %eax,(%rax)
  4020eb:	00 2e                	add    %ch,(%rsi)
  4020ed:	f1                   	icebp  
  4020ee:	ff                   	(bad)  
  4020ef:	ff                   	(bad)  
  4020f0:	38 01                	cmp    %al,(%rcx)
  4020f2:	00 00                	add    %al,(%rax)
  4020f4:	40 f1                	rex icebp 
  4020f6:	ff                   	(bad)  
  4020f7:	ff 58 01             	lcall  *0x1(%rax)
  4020fa:	00 00                	add    %al,(%rax)
  4020fc:	87 f1                	xchg   %esi,%ecx
  4020fe:	ff                   	(bad)  
  4020ff:	ff                   	(bad)  
  402100:	78 01                	js     402103 <__GNU_EH_FRAME_HDR+0x43>
  402102:	00 00                	add    %al,(%rax)
  402104:	4e                   	rex.WRX
  402105:	f2 ff                	repnz (bad) 
  402107:	ff 98 01 00 00 c6    	lcall  *-0x39ffffff(%rax)
  40210d:	f2 ff                	repnz (bad) 
  40210f:	ff                   	(bad)  
  402110:	b8 01 00 00 3e       	mov    $0x3e000001,%eax
  402115:	f3 ff                	repz (bad) 
  402117:	ff                   	(bad)  
  402118:	d8 01                	fadds  (%rcx)
  40211a:	00 00                	add    %al,(%rax)
  40211c:	5f                   	pop    %rdi
  40211d:	f3 ff                	repz (bad) 
  40211f:	ff                   	(bad)  
  402120:	f8                   	clc    
  402121:	01 00                	add    %eax,(%rax)
  402123:	00 a0 f3 ff ff 18    	add    %ah,0x18fffff3(%rax)
  402129:	02 00                	add    (%rax),%al
  40212b:	00 d4                	add    %dl,%ah
  40212d:	f3 ff                	repz (bad) 
  40212f:	ff                   	(bad)  
  402130:	38 02                	cmp    %al,(%rdx)
  402132:	00 00                	add    %al,(%rax)
  402134:	30 f8                	xor    %bh,%al
  402136:	ff                   	(bad)  
  402137:	ff 58 02             	lcall  *0x2(%rax)
  40213a:	00 00                	add    %al,(%rax)
  40213c:	90                   	nop
  40213d:	f8                   	clc    
  40213e:	ff                   	(bad)  
  40213f:	ff                   	.byte 0xff
  402140:	a0                   	.byte 0xa0
  402141:	02 00                	add    (%rax),%al
	...

Disassembly of section .eh_frame:

0000000000402148 <__FRAME_END__-0x22c>:
  402148:	14 00                	adc    $0x0,%al
  40214a:	00 00                	add    %al,(%rax)
  40214c:	00 00                	add    %al,(%rax)
  40214e:	00 00                	add    %al,(%rax)
  402150:	01 7a 52             	add    %edi,0x52(%rdx)
  402153:	00 01                	add    %al,(%rcx)
  402155:	78 10                	js     402167 <__GNU_EH_FRAME_HDR+0xa7>
  402157:	01 1b                	add    %ebx,(%rbx)
  402159:	0c 07                	or     $0x7,%al
  40215b:	08 90 01 07 10 14    	or     %dl,0x14100701(%rax)
  402161:	00 00                	add    %al,(%rax)
  402163:	00 1c 00             	add    %bl,(%rax,%rax,1)
  402166:	00 00                	add    %al,(%rax)
  402168:	48 ef                	rex.W out %eax,(%dx)
  40216a:	ff                   	(bad)  
  40216b:	ff 2b                	ljmp   *(%rbx)
	...
  402175:	00 00                	add    %al,(%rax)
  402177:	00 14 00             	add    %dl,(%rax,%rax,1)
  40217a:	00 00                	add    %al,(%rax)
  40217c:	00 00                	add    %al,(%rax)
  40217e:	00 00                	add    %al,(%rax)
  402180:	01 7a 52             	add    %edi,0x52(%rdx)
  402183:	00 01                	add    %al,(%rcx)
  402185:	78 10                	js     402197 <__GNU_EH_FRAME_HDR+0xd7>
  402187:	01 1b                	add    %ebx,(%rbx)
  402189:	0c 07                	or     $0x7,%al
  40218b:	08 90 01 00 00 24    	or     %dl,0x24000001(%rax)
  402191:	00 00                	add    %al,(%rax)
  402193:	00 1c 00             	add    %bl,(%rax,%rax,1)
  402196:	00 00                	add    %al,(%rax)
  402198:	88 ee                	mov    %ch,%dh
  40219a:	ff                   	(bad)  
  40219b:	ff 90 00 00 00 00    	callq  *0x0(%rax)
  4021a1:	0e                   	(bad)  
  4021a2:	10 46 0e             	adc    %al,0xe(%rsi)
  4021a5:	18 4a 0f             	sbb    %cl,0xf(%rdx)
  4021a8:	0b 77 08             	or     0x8(%rdi),%esi
  4021ab:	80 00 3f             	addb   $0x3f,(%rax)
  4021ae:	1a 3b                	sbb    (%rbx),%bh
  4021b0:	2a 33                	sub    (%rbx),%dh
  4021b2:	24 22                	and    $0x22,%al
  4021b4:	00 00                	add    %al,(%rax)
  4021b6:	00 00                	add    %al,(%rax)
  4021b8:	1c 00                	sbb    $0x0,%al
  4021ba:	00 00                	add    %al,(%rax)
  4021bc:	44 00 00             	add    %r8b,(%rax)
  4021bf:	00 c2                	add    %al,%dl
  4021c1:	ef                   	out    %eax,(%dx)
  4021c2:	ff                   	(bad)  
  4021c3:	ff 07                	incl   (%rdi)
  4021c5:	00 00                	add    %al,(%rax)
  4021c7:	00 00                	add    %al,(%rax)
  4021c9:	41 0e                	rex.B (bad) 
  4021cb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4021d1:	42 0c 07             	rex.X or $0x7,%al
  4021d4:	08 00                	or     %al,(%rax)
  4021d6:	00 00                	add    %al,(%rax)
  4021d8:	1c 00                	sbb    $0x0,%al
  4021da:	00 00                	add    %al,(%rax)
  4021dc:	64 00 00             	add    %al,%fs:(%rax)
  4021df:	00 a9 ef ff ff 65    	add    %ch,0x65ffffef(%rcx)
  4021e5:	00 00                	add    %al,(%rax)
  4021e7:	00 00                	add    %al,(%rax)
  4021e9:	41 0e                	rex.B (bad) 
  4021eb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4021f1:	02 60 0c             	add    0xc(%rax),%ah
  4021f4:	07                   	(bad)  
  4021f5:	08 00                	or     %al,(%rax)
  4021f7:	00 1c 00             	add    %bl,(%rax,%rax,1)
  4021fa:	00 00                	add    %al,(%rax)
  4021fc:	84 00                	test   %al,(%rax)
  4021fe:	00 00                	add    %al,(%rax)
  402200:	ee                   	out    %al,(%dx)
  402201:	ef                   	out    %eax,(%dx)
  402202:	ff                   	(bad)  
  402203:	ff 12                	callq  *(%rdx)
  402205:	00 00                	add    %al,(%rax)
  402207:	00 00                	add    %al,(%rax)
  402209:	41 0e                	rex.B (bad) 
  40220b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  402211:	4d 0c 07             	rex.WRB or $0x7,%al
  402214:	08 00                	or     %al,(%rax)
  402216:	00 00                	add    %al,(%rax)
  402218:	1c 00                	sbb    $0x0,%al
  40221a:	00 00                	add    %al,(%rax)
  40221c:	a4                   	movsb  %ds:(%rsi),%es:(%rdi)
  40221d:	00 00                	add    %al,(%rax)
  40221f:	00 e0                	add    %ah,%al
  402221:	ef                   	out    %eax,(%dx)
  402222:	ff                   	(bad)  
  402223:	ff 47 00             	incl   0x0(%rdi)
  402226:	00 00                	add    %al,(%rax)
  402228:	00 41 0e             	add    %al,0xe(%rcx)
  40222b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  402231:	02 42 0c             	add    0xc(%rdx),%al
  402234:	07                   	(bad)  
  402235:	08 00                	or     %al,(%rax)
  402237:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40223a:	00 00                	add    %al,(%rax)
  40223c:	c4                   	(bad)  
  40223d:	00 00                	add    %al,(%rax)
  40223f:	00 07                	add    %al,(%rdi)
  402241:	f0 ff                	lock (bad) 
  402243:	ff c7                	inc    %edi
  402245:	00 00                	add    %al,(%rax)
  402247:	00 00                	add    %al,(%rax)
  402249:	41 0e                	rex.B (bad) 
  40224b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  402251:	02 c2                	add    %dl,%al
  402253:	0c 07                	or     $0x7,%al
  402255:	08 00                	or     %al,(%rax)
  402257:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40225a:	00 00                	add    %al,(%rax)
  40225c:	e4 00                	in     $0x0,%al
  40225e:	00 00                	add    %al,(%rax)
  402260:	ae                   	scas   %es:(%rdi),%al
  402261:	f0 ff                	lock (bad) 
  402263:	ff                   	(bad)  
  402264:	78 00                	js     402266 <__GNU_EH_FRAME_HDR+0x1a6>
  402266:	00 00                	add    %al,(%rax)
  402268:	00 41 0e             	add    %al,0xe(%rcx)
  40226b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  402271:	02 73 0c             	add    0xc(%rbx),%dh
  402274:	07                   	(bad)  
  402275:	08 00                	or     %al,(%rax)
  402277:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40227a:	00 00                	add    %al,(%rax)
  40227c:	04 01                	add    $0x1,%al
  40227e:	00 00                	add    %al,(%rax)
  402280:	06                   	(bad)  
  402281:	f1                   	icebp  
  402282:	ff                   	(bad)  
  402283:	ff                   	(bad)  
  402284:	78 00                	js     402286 <__GNU_EH_FRAME_HDR+0x1c6>
  402286:	00 00                	add    %al,(%rax)
  402288:	00 41 0e             	add    %al,0xe(%rcx)
  40228b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  402291:	02 73 0c             	add    0xc(%rbx),%dh
  402294:	07                   	(bad)  
  402295:	08 00                	or     %al,(%rax)
  402297:	00 1c 00             	add    %bl,(%rax,%rax,1)
  40229a:	00 00                	add    %al,(%rax)
  40229c:	24 01                	and    $0x1,%al
  40229e:	00 00                	add    %al,(%rax)
  4022a0:	5e                   	pop    %rsi
  4022a1:	f1                   	icebp  
  4022a2:	ff                   	(bad)  
  4022a3:	ff 21                	jmpq   *(%rcx)
  4022a5:	00 00                	add    %al,(%rax)
  4022a7:	00 00                	add    %al,(%rax)
  4022a9:	41 0e                	rex.B (bad) 
  4022ab:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4022b1:	5c                   	pop    %rsp
  4022b2:	0c 07                	or     $0x7,%al
  4022b4:	08 00                	or     %al,(%rax)
  4022b6:	00 00                	add    %al,(%rax)
  4022b8:	1c 00                	sbb    $0x0,%al
  4022ba:	00 00                	add    %al,(%rax)
  4022bc:	44 01 00             	add    %r8d,(%rax)
  4022bf:	00 5f f1             	add    %bl,-0xf(%rdi)
  4022c2:	ff                   	(bad)  
  4022c3:	ff 41 00             	incl   0x0(%rcx)
  4022c6:	00 00                	add    %al,(%rax)
  4022c8:	00 41 0e             	add    %al,0xe(%rcx)
  4022cb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4022d1:	7c 0c                	jl     4022df <__GNU_EH_FRAME_HDR+0x21f>
  4022d3:	07                   	(bad)  
  4022d4:	08 00                	or     %al,(%rax)
  4022d6:	00 00                	add    %al,(%rax)
  4022d8:	1c 00                	sbb    $0x0,%al
  4022da:	00 00                	add    %al,(%rax)
  4022dc:	64 01 00             	add    %eax,%fs:(%rax)
  4022df:	00 80 f1 ff ff 34    	add    %al,0x34fffff1(%rax)
  4022e5:	00 00                	add    %al,(%rax)
  4022e7:	00 00                	add    %al,(%rax)
  4022e9:	41 0e                	rex.B (bad) 
  4022eb:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  4022f1:	6f                   	outsl  %ds:(%rsi),(%dx)
  4022f2:	0c 07                	or     $0x7,%al
  4022f4:	08 00                	or     %al,(%rax)
  4022f6:	00 00                	add    %al,(%rax)
  4022f8:	1c 00                	sbb    $0x0,%al
  4022fa:	00 00                	add    %al,(%rax)
  4022fc:	84 01                	test   %al,(%rcx)
  4022fe:	00 00                	add    %al,(%rax)
  402300:	94                   	xchg   %eax,%esp
  402301:	f1                   	icebp  
  402302:	ff                   	(bad)  
  402303:	ff 4e 04             	decl   0x4(%rsi)
  402306:	00 00                	add    %al,(%rax)
  402308:	00 41 0e             	add    %al,0xe(%rcx)
  40230b:	10 86 02 43 0d 06    	adc    %al,0x60d4302(%rsi)
  402311:	03 49 04             	add    0x4(%rcx),%ecx
  402314:	0c 07                	or     $0x7,%al
  402316:	08 00                	or     %al,(%rax)
  402318:	44 00 00             	add    %r8b,(%rax)
  40231b:	00 a4 01 00 00 d0 f5 	add    %ah,-0xa300000(%rcx,%rax,1)
  402322:	ff                   	(bad)  
  402323:	ff 5d 00             	lcall  *0x0(%rbp)
  402326:	00 00                	add    %al,(%rax)
  402328:	00 42 0e             	add    %al,0xe(%rdx)
  40232b:	10 8f 02 49 0e 18    	adc    %cl,0x180e4902(%rdi)
  402331:	8e 03                	mov    (%rbx),%es
  402333:	45 0e                	rex.RB (bad) 
  402335:	20 8d 04 45 0e 28    	and    %cl,0x280e4504(%rbp)
  40233b:	8c 05 44 0e 30 86    	mov    %es,-0x79cff1bc(%rip)        # ffffffff86703185 <_end+0xffffffff862fd095>
  402341:	06                   	(bad)  
  402342:	48 0e                	rex.W (bad) 
  402344:	38 83 07 47 0e 40    	cmp    %al,0x400e4707(%rbx)
  40234a:	6a 0e                	pushq  $0xe
  40234c:	38 41 0e             	cmp    %al,0xe(%rcx)
  40234f:	30 41 0e             	xor    %al,0xe(%rcx)
  402352:	28 42 0e             	sub    %al,0xe(%rdx)
  402355:	20 42 0e             	and    %al,0xe(%rdx)
  402358:	18 42 0e             	sbb    %al,0xe(%rdx)
  40235b:	10 42 0e             	adc    %al,0xe(%rdx)
  40235e:	08 00                	or     %al,(%rax)
  402360:	10 00                	adc    %al,(%rax)
  402362:	00 00                	add    %al,(%rax)
  402364:	ec                   	in     (%dx),%al
  402365:	01 00                	add    %eax,(%rax)
  402367:	00 e8                	add    %ch,%al
  402369:	f5                   	cmc    
  40236a:	ff                   	(bad)  
  40236b:	ff 01                	incl   (%rcx)
  40236d:	00 00                	add    %al,(%rax)
  40236f:	00 00                	add    %al,(%rax)
  402371:	00 00                	add    %al,(%rax)
	...

0000000000402374 <__FRAME_END__>:
  402374:	00 00                	add    %al,(%rax)
	...

Disassembly of section .init_array:

0000000000403e00 <__frame_dummy_init_array_entry>:
  403e00:	80 11 40             	adcb   $0x40,(%rcx)
  403e03:	00 00                	add    %al,(%rax)
  403e05:	00 00                	add    %al,(%rax)
	...

Disassembly of section .fini_array:

0000000000403e08 <__do_global_dtors_aux_fini_array_entry>:
  403e08:	50                   	push   %rax
  403e09:	11 40 00             	adc    %eax,0x0(%rax)
  403e0c:	00 00                	add    %al,(%rax)
	...

Disassembly of section .dynamic:

0000000000403e10 <_DYNAMIC>:
  403e10:	01 00                	add    %eax,(%rax)
  403e12:	00 00                	add    %al,(%rax)
  403e14:	00 00                	add    %al,(%rax)
  403e16:	00 00                	add    %al,(%rax)
  403e18:	50                   	push   %rax
  403e19:	00 00                	add    %al,(%rax)
  403e1b:	00 00                	add    %al,(%rax)
  403e1d:	00 00                	add    %al,(%rax)
  403e1f:	00 0c 00             	add    %cl,(%rax,%rax,1)
  403e22:	00 00                	add    %al,(%rax)
  403e24:	00 00                	add    %al,(%rax)
  403e26:	00 00                	add    %al,(%rax)
  403e28:	00 10                	add    %dl,(%rax)
  403e2a:	40 00 00             	add    %al,(%rax)
  403e2d:	00 00                	add    %al,(%rax)
  403e2f:	00 0d 00 00 00 00    	add    %cl,0x0(%rip)        # 403e35 <_DYNAMIC+0x25>
  403e35:	00 00                	add    %al,(%rax)
  403e37:	00 54 19 40          	add    %dl,0x40(%rcx,%rbx,1)
  403e3b:	00 00                	add    %al,(%rax)
  403e3d:	00 00                	add    %al,(%rax)
  403e3f:	00 19                	add    %bl,(%rcx)
	...
  403e49:	3e 40 00 00          	add    %al,%ds:(%rax)
  403e4d:	00 00                	add    %al,(%rax)
  403e4f:	00 1b                	add    %bl,(%rbx)
  403e51:	00 00                	add    %al,(%rax)
  403e53:	00 00                	add    %al,(%rax)
  403e55:	00 00                	add    %al,(%rax)
  403e57:	00 08                	add    %cl,(%rax)
  403e59:	00 00                	add    %al,(%rax)
  403e5b:	00 00                	add    %al,(%rax)
  403e5d:	00 00                	add    %al,(%rax)
  403e5f:	00 1a                	add    %bl,(%rdx)
  403e61:	00 00                	add    %al,(%rax)
  403e63:	00 00                	add    %al,(%rax)
  403e65:	00 00                	add    %al,(%rax)
  403e67:	00 08                	add    %cl,(%rax)
  403e69:	3e 40 00 00          	add    %al,%ds:(%rax)
  403e6d:	00 00                	add    %al,(%rax)
  403e6f:	00 1c 00             	add    %bl,(%rax,%rax,1)
  403e72:	00 00                	add    %al,(%rax)
  403e74:	00 00                	add    %al,(%rax)
  403e76:	00 00                	add    %al,(%rax)
  403e78:	08 00                	or     %al,(%rax)
  403e7a:	00 00                	add    %al,(%rax)
  403e7c:	00 00                	add    %al,(%rax)
  403e7e:	00 00                	add    %al,(%rax)
  403e80:	04 00                	add    $0x0,%al
  403e82:	00 00                	add    %al,(%rax)
  403e84:	00 00                	add    %al,(%rax)
  403e86:	00 00                	add    %al,(%rax)
  403e88:	08 03                	or     %al,(%rbx)
  403e8a:	40 00 00             	add    %al,(%rax)
  403e8d:	00 00                	add    %al,(%rax)
  403e8f:	00 f5                	add    %dh,%ch
  403e91:	fe                   	(bad)  
  403e92:	ff 6f 00             	ljmp   *0x0(%rdi)
  403e95:	00 00                	add    %al,(%rax)
  403e97:	00 48 03             	add    %cl,0x3(%rax)
  403e9a:	40 00 00             	add    %al,(%rax)
  403e9d:	00 00                	add    %al,(%rax)
  403e9f:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # 403ea5 <_DYNAMIC+0x95>
  403ea5:	00 00                	add    %al,(%rax)
  403ea7:	00 70 04             	add    %dh,0x4(%rax)
  403eaa:	40 00 00             	add    %al,(%rax)
  403ead:	00 00                	add    %al,(%rax)
  403eaf:	00 06                	add    %al,(%rsi)
  403eb1:	00 00                	add    %al,(%rax)
  403eb3:	00 00                	add    %al,(%rax)
  403eb5:	00 00                	add    %al,(%rax)
  403eb7:	00 68 03             	add    %ch,0x3(%rax)
  403eba:	40 00 00             	add    %al,(%rax)
  403ebd:	00 00                	add    %al,(%rax)
  403ebf:	00 0a                	add    %cl,(%rdx)
  403ec1:	00 00                	add    %al,(%rax)
  403ec3:	00 00                	add    %al,(%rax)
  403ec5:	00 00                	add    %al,(%rax)
  403ec7:	00 75 00             	add    %dh,0x0(%rbp)
  403eca:	00 00                	add    %al,(%rax)
  403ecc:	00 00                	add    %al,(%rax)
  403ece:	00 00                	add    %al,(%rax)
  403ed0:	0b 00                	or     (%rax),%eax
  403ed2:	00 00                	add    %al,(%rax)
  403ed4:	00 00                	add    %al,(%rax)
  403ed6:	00 00                	add    %al,(%rax)
  403ed8:	18 00                	sbb    %al,(%rax)
  403eda:	00 00                	add    %al,(%rax)
  403edc:	00 00                	add    %al,(%rax)
  403ede:	00 00                	add    %al,(%rax)
  403ee0:	15 00 00 00 00       	adc    $0x0,%eax
	...
  403eed:	00 00                	add    %al,(%rax)
  403eef:	00 03                	add    %al,(%rbx)
	...
  403ef9:	40                   	rex
  403efa:	40 00 00             	add    %al,(%rax)
  403efd:	00 00                	add    %al,(%rax)
  403eff:	00 02                	add    %al,(%rdx)
  403f01:	00 00                	add    %al,(%rax)
  403f03:	00 00                	add    %al,(%rax)
  403f05:	00 00                	add    %al,(%rax)
  403f07:	00 c0                	add    %al,%al
  403f09:	00 00                	add    %al,(%rax)
  403f0b:	00 00                	add    %al,(%rax)
  403f0d:	00 00                	add    %al,(%rax)
  403f0f:	00 14 00             	add    %dl,(%rax,%rax,1)
  403f12:	00 00                	add    %al,(%rax)
  403f14:	00 00                	add    %al,(%rax)
  403f16:	00 00                	add    %al,(%rax)
  403f18:	07                   	(bad)  
  403f19:	00 00                	add    %al,(%rax)
  403f1b:	00 00                	add    %al,(%rax)
  403f1d:	00 00                	add    %al,(%rax)
  403f1f:	00 17                	add    %dl,(%rdi)
  403f21:	00 00                	add    %al,(%rax)
  403f23:	00 00                	add    %al,(%rax)
  403f25:	00 00                	add    %al,(%rax)
  403f27:	00 50 05             	add    %dl,0x5(%rax)
  403f2a:	40 00 00             	add    %al,(%rax)
  403f2d:	00 00                	add    %al,(%rax)
  403f2f:	00 07                	add    %al,(%rdi)
  403f31:	00 00                	add    %al,(%rax)
  403f33:	00 00                	add    %al,(%rax)
  403f35:	00 00                	add    %al,(%rax)
  403f37:	00 20                	add    %ah,(%rax)
  403f39:	05 40 00 00 00       	add    $0x40,%eax
  403f3e:	00 00                	add    %al,(%rax)
  403f40:	08 00                	or     %al,(%rax)
  403f42:	00 00                	add    %al,(%rax)
  403f44:	00 00                	add    %al,(%rax)
  403f46:	00 00                	add    %al,(%rax)
  403f48:	30 00                	xor    %al,(%rax)
  403f4a:	00 00                	add    %al,(%rax)
  403f4c:	00 00                	add    %al,(%rax)
  403f4e:	00 00                	add    %al,(%rax)
  403f50:	09 00                	or     %eax,(%rax)
  403f52:	00 00                	add    %al,(%rax)
  403f54:	00 00                	add    %al,(%rax)
  403f56:	00 00                	add    %al,(%rax)
  403f58:	18 00                	sbb    %al,(%rax)
  403f5a:	00 00                	add    %al,(%rax)
  403f5c:	00 00                	add    %al,(%rax)
  403f5e:	00 00                	add    %al,(%rax)
  403f60:	fe                   	(bad)  
  403f61:	ff                   	(bad)  
  403f62:	ff 6f 00             	ljmp   *0x0(%rdi)
  403f65:	00 00                	add    %al,(%rax)
  403f67:	00 00                	add    %al,(%rax)
  403f69:	05 40 00 00 00       	add    $0x40,%eax
  403f6e:	00 00                	add    %al,(%rax)
  403f70:	ff                   	(bad)  
  403f71:	ff                   	(bad)  
  403f72:	ff 6f 00             	ljmp   *0x0(%rdi)
  403f75:	00 00                	add    %al,(%rax)
  403f77:	00 01                	add    %al,(%rcx)
  403f79:	00 00                	add    %al,(%rax)
  403f7b:	00 00                	add    %al,(%rax)
  403f7d:	00 00                	add    %al,(%rax)
  403f7f:	00 f0                	add    %dh,%al
  403f81:	ff                   	(bad)  
  403f82:	ff 6f 00             	ljmp   *0x0(%rdi)
  403f85:	00 00                	add    %al,(%rax)
  403f87:	00 e6                	add    %ah,%dh
  403f89:	04 40                	add    $0x40,%al
	...

Disassembly of section .got:

0000000000403ff0 <.got>:
	...

Disassembly of section .got.plt:

0000000000404000 <_GLOBAL_OFFSET_TABLE_>:
  404000:	10 3e                	adc    %bh,(%rsi)
  404002:	40 00 00             	add    %al,(%rax)
	...
  404015:	00 00                	add    %al,(%rax)
  404017:	00 36                	add    %dh,(%rsi)
  404019:	10 40 00             	adc    %al,0x0(%rax)
  40401c:	00 00                	add    %al,(%rax)
  40401e:	00 00                	add    %al,(%rax)
  404020:	46 10 40 00          	rex.RX adc %r8b,0x0(%rax)
  404024:	00 00                	add    %al,(%rax)
  404026:	00 00                	add    %al,(%rax)
  404028:	56                   	push   %rsi
  404029:	10 40 00             	adc    %al,0x0(%rax)
  40402c:	00 00                	add    %al,(%rax)
  40402e:	00 00                	add    %al,(%rax)
  404030:	66 10 40 00          	data16 adc %al,0x0(%rax)
  404034:	00 00                	add    %al,(%rax)
  404036:	00 00                	add    %al,(%rax)
  404038:	76 10                	jbe    40404a <_GLOBAL_OFFSET_TABLE_+0x4a>
  40403a:	40 00 00             	add    %al,(%rax)
  40403d:	00 00                	add    %al,(%rax)
  40403f:	00 86 10 40 00 00    	add    %al,0x4010(%rsi)
  404045:	00 00                	add    %al,(%rax)
  404047:	00 96 10 40 00 00    	add    %dl,0x4010(%rsi)
  40404d:	00 00                	add    %al,(%rax)
  40404f:	00 a6 10 40 00 00    	add    %ah,0x4010(%rsi)
  404055:	00 00                	add    %al,(%rax)
	...

Disassembly of section .data:

0000000000404058 <__data_start>:
	...

0000000000404060 <__dso_handle>:
	...

Disassembly of section .bss:

0000000000404080 <completed.0>:
	...

00000000004040a0 <oraclearr>:
	...

00000000004040a8 <tmp_store>:
	...

00000000004040b0 <addr1>:
	...

00000000004040b8 <addr2>:
	...

00000000004040c0 <addr3>:
	...

00000000004040c8 <tlb_fd>:
	...

00000000004040e0 <shadow_offset>:
	...

00000000004050e0 <averg>:
	...

00000000004058e0 <averg_rnd>:
	...

00000000004060e0 <memsize>:
	...

00000000004060e8 <mem>:
	...

Disassembly of section .comment:

0000000000000000 <.comment>:
   0:	47                   	rex.RXB
   1:	43                   	rex.XB
   2:	43 3a 20             	rex.XB cmp (%r8),%spl
   5:	28 53 55             	sub    %dl,0x55(%rbx)
   8:	53                   	push   %rbx
   9:	45 20 4c 69 6e       	and    %r9b,0x6e(%r9,%rbp,2)
   e:	75 78                	jne    88 <_init-0x400f78>
  10:	29 20                	sub    %esp,(%rax)
  12:	31 30                	xor    %esi,(%rax)
  14:	2e 31 2e             	xor    %ebp,%cs:(%rsi)
  17:	31 20                	xor    %esp,(%rax)
  19:	32 30                	xor    (%rax),%dh
  1b:	32 30                	xor    (%rax),%dh
  1d:	30 35 30 37 20 5b    	xor    %dh,0x5b203730(%rip)        # 5b203753 <_end+0x5adfd663>
  23:	72 65                	jb     8a <_init-0x400f76>
  25:	76 69                	jbe    90 <_init-0x400f70>
  27:	73 69                	jae    92 <_init-0x400f6e>
  29:	6f                   	outsl  %ds:(%rsi),(%dx)
  2a:	6e                   	outsb  %ds:(%rsi),(%dx)
  2b:	20 64 64 33          	and    %ah,0x33(%rsp,%riz,2)
  2f:	38 36                	cmp    %dh,(%rsi)
  31:	38 36                	cmp    %dh,(%rsi)
  33:	64 39 63 38          	cmp    %esp,%fs:0x38(%rbx)
  37:	31 30                	xor    %esi,(%rax)
  39:	63 65 63             	movslq 0x63(%rbp),%esp
  3c:	62 61                	(bad)  
  3e:	61                   	(bad)  
  3f:	38 30                	cmp    %dh,(%rax)
  41:	62 62                	(bad)  
  43:	38 32                	cmp    %dh,(%rdx)
  45:	65 64 39 31          	gs cmp %esi,%fs:(%rcx)
  49:	63 61 61             	movslq 0x61(%rcx),%esp
  4c:	61                   	(bad)  
  4d:	35 38 61 64 36       	xor    $0x36646138,%eax
  52:	33                   	.byte 0x33
  53:	35                   	.byte 0x35
  54:	5d                   	pop    %rbp
	...

Disassembly of section .debug_aranges:

0000000000000000 <.debug_aranges>:
   0:	2c 00                	sub    $0x0,%al
   2:	00 00                	add    %al,(%rax)
   4:	02 00                	add    (%rax),%al
   6:	00 00                	add    %al,(%rax)
   8:	00 00                	add    %al,(%rax)
   a:	08 00                	or     %al,(%rax)
   c:	00 00                	add    %al,(%rax)
   e:	00 00                	add    %al,(%rax)
  10:	b0 10                	mov    $0x10,%al
  12:	40 00 00             	add    %al,(%rax)
  15:	00 00                	add    %al,(%rax)
  17:	00 2b                	add    %ch,(%rbx)
	...
  2d:	00 00                	add    %al,(%rax)
  2f:	00 1c 00             	add    %bl,(%rax,%rax,1)
  32:	00 00                	add    %al,(%rax)
  34:	02 00                	add    (%rax),%al
  36:	2e 00 00             	add    %al,%cs:(%rax)
  39:	00 08                	add    %cl,(%rax)
	...
  4f:	00 3c 00             	add    %bh,(%rax,%rax,1)
  52:	00 00                	add    %al,(%rax)
  54:	02 00                	add    (%rax),%al
  56:	6e                   	outsb  %ds:(%rsi),(%dx)
  57:	00 00                	add    %al,(%rax)
  59:	00 08                	add    %cl,(%rax)
  5b:	00 00                	add    %al,(%rax)
  5d:	00 00                	add    %al,(%rax)
  5f:	00 00                	add    %al,(%rax)
  61:	10 40 00             	adc    %al,0x0(%rax)
  64:	00 00                	add    %al,(%rax)
  66:	00 00                	add    %al,(%rax)
  68:	12 00                	adc    (%rax),%al
  6a:	00 00                	add    %al,(%rax)
  6c:	00 00                	add    %al,(%rax)
  6e:	00 00                	add    %al,(%rax)
  70:	54                   	push   %rsp
  71:	19 40 00             	sbb    %eax,0x0(%rax)
  74:	00 00                	add    %al,(%rax)
  76:	00 00                	add    %al,(%rax)
  78:	04 00                	add    $0x0,%al
	...
  8e:	00 00                	add    %al,(%rax)
  90:	2c 00                	sub    $0x0,%al
  92:	00 00                	add    %al,(%rax)
  94:	02 00                	add    (%rax),%al
  96:	90                   	nop
  97:	00 00                	add    %al,(%rax)
  99:	00 08                	add    %cl,(%rax)
  9b:	00 00                	add    %al,(%rax)
  9d:	00 00                	add    %al,(%rax)
  9f:	00 f0                	add    %dh,%al
  a1:	18 40 00             	sbb    %al,0x0(%rax)
  a4:	00 00                	add    %al,(%rax)
  a6:	00 00                	add    %al,(%rax)
  a8:	61                   	(bad)  
	...
  bd:	00 00                	add    %al,(%rax)
  bf:	00 3c 00             	add    %bh,(%rax,%rax,1)
  c2:	00 00                	add    %al,(%rax)
  c4:	02 00                	add    (%rax),%al
  c6:	29 02                	sub    %eax,(%rdx)
  c8:	00 00                	add    %al,(%rax)
  ca:	08 00                	or     %al,(%rax)
  cc:	00 00                	add    %al,(%rax)
  ce:	00 00                	add    %al,(%rax)
  d0:	12 10                	adc    (%rax),%dl
  d2:	40 00 00             	add    %al,(%rax)
  d5:	00 00                	add    %al,(%rax)
  d7:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # dd <_init-0x400f23>
  dd:	00 00                	add    %al,(%rax)
  df:	00 58 19             	add    %bl,0x19(%rax)
  e2:	40 00 00             	add    %al,(%rax)
  e5:	00 00                	add    %al,(%rax)
  e7:	00 05 00 00 00 00    	add    %al,0x0(%rip)        # ed <_init-0x400f13>
	...

Disassembly of section .debug_info:

0000000000000000 <.debug_info>:
   0:	2a 00                	sub    (%rax),%al
   2:	00 00                	add    %al,(%rax)
   4:	02 00                	add    (%rax),%al
   6:	00 00                	add    %al,(%rax)
   8:	00 00                	add    %al,(%rax)
   a:	08 01                	or     %al,(%rcx)
   c:	00 00                	add    %al,(%rax)
   e:	00 00                	add    %al,(%rax)
  10:	b0 10                	mov    $0x10,%al
  12:	40 00 00             	add    %al,(%rax)
  15:	00 00                	add    %al,(%rax)
  17:	00 db                	add    %bl,%bl
  19:	10 40 00             	adc    %al,0x0(%rax)
	...
  24:	1a 00                	sbb    (%rax),%al
  26:	00 00                	add    %al,(%rax)
  28:	45 00 00             	add    %r8b,(%r8)
  2b:	00 01                	add    %al,(%rcx)
  2d:	80 3c 00 00          	cmpb   $0x0,(%rax,%rax,1)
  31:	00 04 00             	add    %al,(%rax,%rax,1)
  34:	14 00                	adc    $0x0,%al
  36:	00 00                	add    %al,(%rax)
  38:	08 01                	or     %al,(%rcx)
  3a:	62                   	(bad)  
  3b:	00 00                	add    %al,(%rax)
  3d:	00 0c 0e             	add    %cl,(%rsi,%rcx,1)
  40:	02 00                	add    (%rax),%al
  42:	00 1a                	add    %bl,(%rdx)
  44:	00 00                	add    %al,(%rax)
  46:	00 5c 00 00          	add    %bl,0x0(%rax,%rax,1)
  4a:	00 02                	add    %al,(%rdx)
  4c:	53                   	push   %rbx
  4d:	00 00                	add    %al,(%rax)
  4f:	00 01                	add    %al,(%rcx)
  51:	17                   	(bad)  
  52:	0b 3a                	or     (%rdx),%edi
  54:	00 00                	add    %al,(%rax)
  56:	00 09                	add    %cl,(%rcx)
  58:	03 00                	add    (%rax),%eax
  5a:	20 40 00             	and    %al,0x0(%rax)
  5d:	00 00                	add    %al,(%rax)
  5f:	00 00                	add    %al,(%rax)
  61:	03 04 05 69 6e 74 00 	add    0x746e69(,%rax,1),%eax
  68:	04 33                	add    $0x33,%al
  6a:	00 00                	add    %al,(%rax)
  6c:	00 00                	add    %al,(%rax)
  6e:	1e                   	(bad)  
  6f:	00 00                	add    %al,(%rax)
  71:	00 02                	add    %al,(%rdx)
  73:	00 49 00             	add    %cl,0x0(%rcx)
  76:	00 00                	add    %al,(%rax)
  78:	08 01                	or     %al,(%rcx)
  7a:	83 00 00             	addl   $0x0,(%rax)
  7d:	00 00                	add    %al,(%rax)
  7f:	00 00                	add    %al,(%rax)
  81:	00 c4                	add    %al,%ah
  83:	01 00                	add    %eax,(%rax)
  85:	00 1a                	add    %bl,(%rdx)
  87:	00 00                	add    %al,(%rax)
  89:	00 45 00             	add    %al,0x0(%rbp)
  8c:	00 00                	add    %al,(%rax)
  8e:	01 80 95 01 00 00    	add    %eax,0x195(%rax)
  94:	04 00                	add    $0x0,%al
  96:	5b                   	pop    %rbx
  97:	00 00                	add    %al,(%rax)
  99:	00 08                	add    %cl,(%rax)
  9b:	01 37                	add    %esi,(%rdi)
  9d:	02 00                	add    (%rax),%al
  9f:	00 0c 0a             	add    %cl,(%rdx,%rcx,1)
  a2:	02 00                	add    (%rax),%al
  a4:	00 1a                	add    %bl,(%rdx)
  a6:	00 00                	add    %al,(%rax)
  a8:	00 f0                	add    %dh,%al
  aa:	18 40 00             	sbb    %al,0x0(%rax)
  ad:	00 00                	add    %al,(%rax)
  af:	00 00                	add    %al,(%rax)
  b1:	61                   	(bad)  
  b2:	00 00                	add    %al,(%rax)
  b4:	00 00                	add    %al,(%rax)
  b6:	00 00                	add    %al,(%rax)
  b8:	00 e8                	add    %ch,%al
  ba:	00 00                	add    %al,(%rax)
  bc:	00 02                	add    %al,(%rdx)
  be:	08 05 e2 01 00 00    	or     %al,0x1e2(%rip)        # 2a6 <_init-0x400d5a>
  c4:	03 eb                	add    %ebx,%ebp
  c6:	01 00                	add    %eax,(%rax)
  c8:	00 02                	add    %al,(%rdx)
  ca:	d1 17                	rcll   (%rdi)
  cc:	45 00 00             	add    %r8b,(%r8)
  cf:	00 04 34             	add    %al,(%rsp,%rsi,1)
  d2:	00 00                	add    %al,(%rax)
  d4:	00 02                	add    %al,(%rdx)
  d6:	08 07                	or     %al,(%rdi)
  d8:	15 02 00 00 05       	adc    $0x5000002,%eax
  dd:	04 05                	add    $0x5,%al
  df:	69 6e 74 00 02 08 05 	imul   $0x5080200,0x74(%rsi),%ebp
  e6:	dd 01                	fldl   (%rcx)
  e8:	00 00                	add    %al,(%rax)
  ea:	02 10                	add    (%rax),%dl
  ec:	04 c7                	add    $0xc7,%al
  ee:	03 00                	add    (%rax),%eax
  f0:	00 06                	add    %al,(%rsi)
  f2:	6c                   	insb   (%dx),%es:(%rdi)
  f3:	00 00                	add    %al,(%rax)
  f5:	00 6c 00 00          	add    %ch,0x0(%rax,%rax,1)
  f9:	00 07                	add    %al,(%rdi)
  fb:	00 08                	add    %cl,(%rax)
  fd:	08 72 00             	or     %dh,0x0(%rdx)
 100:	00 00                	add    %al,(%rax)
 102:	09 87 00 00 00 0a    	or     %eax,0xa000000(%rdi)
 108:	4c 00 00             	rex.WR add %r8b,(%rax)
 10b:	00 0a                	add    %cl,(%rdx)
 10d:	87 00                	xchg   %eax,(%rax)
 10f:	00 00                	add    %al,(%rax)
 111:	0a 87 00 00 00 00    	or     0x0(%rdi),%al
 117:	08 08                	or     %cl,(%rax)
 119:	8d 00                	lea    (%rax),%eax
 11b:	00 00                	add    %al,(%rax)
 11d:	08 08                	or     %cl,(%rax)
 11f:	93                   	xchg   %eax,%ebx
 120:	00 00                	add    %al,(%rax)
 122:	00 02                	add    %al,(%rdx)
 124:	01 06                	add    %eax,(%rsi)
 126:	a3 03 00 00 0b f2 01 	movabs %eax,0x1f20b000003
 12d:	00 00 
 12f:	01 2c 0f             	add    %ebp,(%rdi,%rcx,1)
 132:	61                   	(bad)  
 133:	00 00                	add    %al,(%rax)
 135:	00 0b                	add    %cl,(%rbx)
 137:	d3 03                	roll   %cl,(%rbx)
 139:	00 00                	add    %al,(%rax)
 13b:	01 2e                	add    %ebp,(%rsi)
 13d:	0f 61 00             	punpcklwd (%rax),%mm0
 140:	00 00                	add    %al,(%rax)
 142:	0c 27                	or     $0x27,%al
 144:	02 00                	add    (%rax),%al
 146:	00 01                	add    %al,(%rcx)
 148:	5f                   	pop    %rdi
 149:	01 50 19             	add    %edx,0x19(%rax)
 14c:	40 00 00             	add    %al,(%rax)
 14f:	00 00                	add    %al,(%rax)
 151:	00 01                	add    %al,(%rcx)
 153:	00 00                	add    %al,(%rax)
 155:	00 00                	add    %al,(%rax)
 157:	00 00                	add    %al,(%rax)
 159:	00 01                	add    %al,(%rcx)
 15b:	9c                   	pushfq 
 15c:	0d b2 03 00 00       	or     $0x3b2,%eax
 161:	01 43 01             	add    %eax,0x1(%rbx)
 164:	f0 18 40 00          	lock sbb %al,0x0(%rax)
 168:	00 00                	add    %al,(%rax)
 16a:	00 00                	add    %al,(%rax)
 16c:	5d                   	pop    %rbp
 16d:	00 00                	add    %al,(%rax)
 16f:	00 00                	add    %al,(%rax)
 171:	00 00                	add    %al,(%rax)
 173:	00 01                	add    %al,(%rcx)
 175:	9c                   	pushfq 
 176:	8c 01                	mov    %es,(%rcx)
 178:	00 00                	add    %al,(%rax)
 17a:	0e                   	(bad)  
 17b:	a8 03                	test   $0x3,%al
 17d:	00 00                	add    %al,(%rax)
 17f:	01 43 16             	add    %eax,0x16(%rbx)
 182:	4c 00 00             	rex.WR add %r8b,(%rax)
 185:	00 06                	add    %al,(%rsi)
 187:	00 00                	add    %al,(%rax)
 189:	00 00                	add    %al,(%rax)
 18b:	00 00                	add    %al,(%rax)
 18d:	00 0e                	add    %cl,(%rsi)
 18f:	c2 03 00             	retq   $0x3
 192:	00 01                	add    %al,(%rcx)
 194:	43 23 87 00 00 00 58 	rex.XB and 0x58000000(%r15),%eax
 19b:	00 00                	add    %al,(%rax)
 19d:	00 52 00             	add    %dl,0x0(%rdx)
 1a0:	00 00                	add    %al,(%rax)
 1a2:	0e                   	(bad)  
 1a3:	05 02 00 00 01       	add    $0x1000002,%eax
 1a8:	43 30 87 00 00 00 aa 	rex.XB xor %al,-0x56000000(%r15)
 1af:	00 00                	add    %al,(%rax)
 1b1:	00 a4 00 00 00 0f ad 	add    %ah,-0x52f10000(%rax,%rax,1)
 1b8:	03 00                	add    (%rax),%eax
 1ba:	00 01                	add    %al,(%rcx)
 1bc:	56                   	push   %rsi
 1bd:	10 40 00             	adc    %al,0x0(%rax)
 1c0:	00 00                	add    %al,(%rax)
 1c2:	fa                   	cli    
 1c3:	00 00                	add    %al,(%rax)
 1c5:	00 f6                	add    %dh,%dh
 1c7:	00 00                	add    %al,(%rax)
 1c9:	00 10                	add    %dl,(%rax)
 1cb:	1d 19 40 00 00       	sbb    $0x4019,%eax
 1d0:	00 00                	add    %al,(%rax)
 1d2:	00 21                	add    %ah,(%rcx)
 1d4:	00 00                	add    %al,(%rax)
 1d6:	00 00                	add    %al,(%rax)
 1d8:	00 00                	add    %al,(%rax)
 1da:	00 7e 01             	add    %bh,0x1(%rsi)
 1dd:	00 00                	add    %al,(%rax)
 1df:	11 69 00             	adc    %ebp,0x0(%rcx)
 1e2:	01 57 0f             	add    %edx,0xf(%rdi)
 1e5:	34 00                	xor    $0x0,%al
 1e7:	00 00                	add    %al,(%rax)
 1e9:	38 01                	cmp    %al,(%rcx)
 1eb:	00 00                	add    %al,(%rax)
 1ed:	34 01                	xor    $0x1,%al
 1ef:	00 00                	add    %al,(%rax)
 1f1:	12 35 19 40 00 00    	adc    0x4019(%rip),%dh        # 4210 <_init-0x3fcdf0>
 1f7:	00 00                	add    %al,(%rax)
 1f9:	00 13                	add    %dl,(%rbx)
 1fb:	01 55 02             	add    %edx,0x2(%rbp)
 1fe:	7c 00                	jl     200 <_init-0x400e00>
 200:	13 01                	adc    (%rcx),%eax
 202:	54                   	push   %rsp
 203:	02 7d 00             	add    0x0(%rbp),%bh
 206:	13 01                	adc    (%rcx),%eax
 208:	51                   	push   %rcx
 209:	02 7e 00             	add    0x0(%rsi),%bh
 20c:	00 00                	add    %al,(%rax)
 20e:	14 1d                	adc    $0x1d,%al
 210:	19 40 00             	sbb    %eax,0x0(%rax)
 213:	00 00                	add    %al,(%rax)
 215:	00 00                	add    %al,(%rax)
 217:	8c 01                	mov    %es,(%rcx)
 219:	00 00                	add    %al,(%rax)
 21b:	00 15 bc 03 00 00    	add    %dl,0x3bc(%rip)        # 5dd <_init-0x400a23>
 221:	bc 03 00 00 01       	mov    $0x1000003,%esp
 226:	37                   	(bad)  
 227:	0d 00 1e 00 00       	or     $0x1e00,%eax
 22c:	00 02                	add    %al,(%rdx)
 22e:	00 85 01 00 00 08    	add    %al,0x8000001(%rbp)
 234:	01 e2                	add    %esp,%edx
 236:	01 00                	add    %eax,(%rax)
 238:	00 40 00             	add    %al,0x0(%rax)
 23b:	00 00                	add    %al,(%rax)
 23d:	e4 03                	in     $0x3,%al
 23f:	00 00                	add    %al,(%rax)
 241:	1a 00                	sbb    (%rax),%al
 243:	00 00                	add    %al,(%rax)
 245:	45 00 00             	add    %r8b,(%r8)
 248:	00 01                	add    %al,(%rcx)
 24a:	80                   	.byte 0x80

Disassembly of section .debug_abbrev:

0000000000000000 <.debug_abbrev>:
   0:	01 11                	add    %edx,(%rcx)
   2:	00 10                	add    %dl,(%rax)
   4:	06                   	(bad)  
   5:	11 01                	adc    %eax,(%rcx)
   7:	12 01                	adc    (%rcx),%al
   9:	03 0e                	add    (%rsi),%ecx
   b:	1b 0e                	sbb    (%rsi),%ecx
   d:	25 0e 13 05 00       	and    $0x5130e,%eax
  12:	00 00                	add    %al,(%rax)
  14:	01 11                	add    %edx,(%rcx)
  16:	01 25 0e 13 0b 03    	add    %esp,0x30b130e(%rip)        # 30b132a <_end+0x2cab23a>
  1c:	0e                   	(bad)  
  1d:	1b 0e                	sbb    (%rsi),%ecx
  1f:	10 17                	adc    %dl,(%rdi)
  21:	00 00                	add    %al,(%rax)
  23:	02 34 00             	add    (%rax,%rax,1),%dh
  26:	03 0e                	add    (%rsi),%ecx
  28:	3a 0b                	cmp    (%rbx),%cl
  2a:	3b 0b                	cmp    (%rbx),%ecx
  2c:	39 0b                	cmp    %ecx,(%rbx)
  2e:	49 13 3f             	adc    (%r15),%rdi
  31:	19 02                	sbb    %eax,(%rdx)
  33:	18 00                	sbb    %al,(%rax)
  35:	00 03                	add    %al,(%rbx)
  37:	24 00                	and    $0x0,%al
  39:	0b 0b                	or     (%rbx),%ecx
  3b:	3e 0b 03             	or     %ds:(%rbx),%eax
  3e:	08 00                	or     %al,(%rax)
  40:	00 04 26             	add    %al,(%rsi,%riz,1)
  43:	00 49 13             	add    %cl,0x13(%rcx)
  46:	00 00                	add    %al,(%rax)
  48:	00 01                	add    %al,(%rcx)
  4a:	11 00                	adc    %eax,(%rax)
  4c:	10 06                	adc    %al,(%rsi)
  4e:	55                   	push   %rbp
  4f:	06                   	(bad)  
  50:	03 0e                	add    (%rsi),%ecx
  52:	1b 0e                	sbb    (%rsi),%ecx
  54:	25 0e 13 05 00       	and    $0x5130e,%eax
  59:	00 00                	add    %al,(%rax)
  5b:	01 11                	add    %edx,(%rcx)
  5d:	01 25 0e 13 0b 03    	add    %esp,0x30b130e(%rip)        # 30b1371 <_end+0x2cab281>
  63:	0e                   	(bad)  
  64:	1b 0e                	sbb    (%rsi),%ecx
  66:	11 01                	adc    %eax,(%rcx)
  68:	12 07                	adc    (%rdi),%al
  6a:	10 17                	adc    %dl,(%rdi)
  6c:	00 00                	add    %al,(%rax)
  6e:	02 24 00             	add    (%rax,%rax,1),%ah
  71:	0b 0b                	or     (%rbx),%ecx
  73:	3e 0b 03             	or     %ds:(%rbx),%eax
  76:	0e                   	(bad)  
  77:	00 00                	add    %al,(%rax)
  79:	03 16                	add    (%rsi),%edx
  7b:	00 03                	add    %al,(%rbx)
  7d:	0e                   	(bad)  
  7e:	3a 0b                	cmp    (%rbx),%cl
  80:	3b 0b                	cmp    (%rbx),%ecx
  82:	39 0b                	cmp    %ecx,(%rbx)
  84:	49 13 00             	adc    (%r8),%rax
  87:	00 04 26             	add    %al,(%rsi,%riz,1)
  8a:	00 49 13             	add    %cl,0x13(%rcx)
  8d:	00 00                	add    %al,(%rax)
  8f:	05 24 00 0b 0b       	add    $0xb0b0024,%eax
  94:	3e 0b 03             	or     %ds:(%rbx),%eax
  97:	08 00                	or     %al,(%rax)
  99:	00 06                	add    %al,(%rsi)
  9b:	01 01                	add    %eax,(%rcx)
  9d:	49 13 01             	adc    (%r9),%rax
  a0:	13 00                	adc    (%rax),%eax
  a2:	00 07                	add    %al,(%rdi)
  a4:	21 00                	and    %eax,(%rax)
  a6:	00 00                	add    %al,(%rax)
  a8:	08 0f                	or     %cl,(%rdi)
  aa:	00 0b                	add    %cl,(%rbx)
  ac:	0b 49 13             	or     0x13(%rcx),%ecx
  af:	00 00                	add    %al,(%rax)
  b1:	09 15 01 27 19 01    	or     %edx,0x1192701(%rip)        # 11927b8 <_end+0xd8c6c8>
  b7:	13 00                	adc    (%rax),%eax
  b9:	00 0a                	add    %cl,(%rdx)
  bb:	05 00 49 13 00       	add    $0x134900,%eax
  c0:	00 0b                	add    %cl,(%rbx)
  c2:	34 00                	xor    $0x0,%al
  c4:	03 0e                	add    (%rsi),%ecx
  c6:	3a 0b                	cmp    (%rbx),%cl
  c8:	3b 0b                	cmp    (%rbx),%ecx
  ca:	39 0b                	cmp    %ecx,(%rbx)
  cc:	49 13 3f             	adc    (%r15),%rdi
  cf:	19 3c 19             	sbb    %edi,(%rcx,%rbx,1)
  d2:	00 00                	add    %al,(%rax)
  d4:	0c 2e                	or     $0x2e,%al
  d6:	00 3f                	add    %bh,(%rdi)
  d8:	19 03                	sbb    %eax,(%rbx)
  da:	0e                   	(bad)  
  db:	3a 0b                	cmp    (%rbx),%cl
  dd:	3b 0b                	cmp    (%rbx),%ecx
  df:	39 0b                	cmp    %ecx,(%rbx)
  e1:	27                   	(bad)  
  e2:	19 11                	sbb    %edx,(%rcx)
  e4:	01 12                	add    %edx,(%rdx)
  e6:	07                   	(bad)  
  e7:	40 18 97 42 19 00 00 	sbb    %dl,0x1942(%rdi)
  ee:	0d 2e 01 3f 19       	or     $0x193f012e,%eax
  f3:	03 0e                	add    (%rsi),%ecx
  f5:	3a 0b                	cmp    (%rbx),%cl
  f7:	3b 0b                	cmp    (%rbx),%ecx
  f9:	39 0b                	cmp    %ecx,(%rbx)
  fb:	27                   	(bad)  
  fc:	19 11                	sbb    %edx,(%rcx)
  fe:	01 12                	add    %edx,(%rdx)
 100:	07                   	(bad)  
 101:	40 18 97 42 19 01 13 	sbb    %dl,0x13011942(%rdi)
 108:	00 00                	add    %al,(%rax)
 10a:	0e                   	(bad)  
 10b:	05 00 03 0e 3a       	add    $0x3a0e0300,%eax
 110:	0b 3b                	or     (%rbx),%edi
 112:	0b 39                	or     (%rcx),%edi
 114:	0b 49 13             	or     0x13(%rcx),%ecx
 117:	02 17                	add    (%rdi),%dl
 119:	b7 42                	mov    $0x42,%bh
 11b:	17                   	(bad)  
 11c:	00 00                	add    %al,(%rax)
 11e:	0f 34                	sysenter 
 120:	00 03                	add    %al,(%rbx)
 122:	0e                   	(bad)  
 123:	3a 0b                	cmp    (%rbx),%cl
 125:	3b 0b                	cmp    (%rbx),%ecx
 127:	39 0b                	cmp    %ecx,(%rbx)
 129:	49 13 02             	adc    (%r10),%rax
 12c:	17                   	(bad)  
 12d:	b7 42                	mov    $0x42,%bh
 12f:	17                   	(bad)  
 130:	00 00                	add    %al,(%rax)
 132:	10 0b                	adc    %cl,(%rbx)
 134:	01 11                	add    %edx,(%rcx)
 136:	01 12                	add    %edx,(%rdx)
 138:	07                   	(bad)  
 139:	01 13                	add    %edx,(%rbx)
 13b:	00 00                	add    %al,(%rax)
 13d:	11 34 00             	adc    %esi,(%rax,%rax,1)
 140:	03 08                	add    (%rax),%ecx
 142:	3a 0b                	cmp    (%rbx),%cl
 144:	3b 0b                	cmp    (%rbx),%ecx
 146:	39 0b                	cmp    %ecx,(%rbx)
 148:	49 13 02             	adc    (%r10),%rax
 14b:	17                   	(bad)  
 14c:	b7 42                	mov    $0x42,%bh
 14e:	17                   	(bad)  
 14f:	00 00                	add    %al,(%rax)
 151:	12 89 82 01 01 11    	adc    0x11010182(%rcx),%cl
 157:	01 00                	add    %eax,(%rax)
 159:	00 13                	add    %dl,(%rbx)
 15b:	8a 82 01 00 02 18    	mov    0x18020001(%rdx),%al
 161:	91                   	xchg   %eax,%ecx
 162:	42 18 00             	rex.X sbb %al,(%rax)
 165:	00 14 89             	add    %dl,(%rcx,%rcx,4)
 168:	82                   	(bad)  
 169:	01 00                	add    %eax,(%rax)
 16b:	11 01                	adc    %eax,(%rcx)
 16d:	31 13                	xor    %edx,(%rbx)
 16f:	00 00                	add    %al,(%rax)
 171:	15 2e 00 3f 19       	adc    $0x193f002e,%eax
 176:	3c 19                	cmp    $0x19,%al
 178:	6e                   	outsb  %ds:(%rsi),(%dx)
 179:	0e                   	(bad)  
 17a:	03 0e                	add    (%rsi),%ecx
 17c:	3a 0b                	cmp    (%rbx),%cl
 17e:	3b 0b                	cmp    (%rbx),%ecx
 180:	39 0b                	cmp    %ecx,(%rbx)
 182:	00 00                	add    %al,(%rax)
 184:	00 01                	add    %al,(%rcx)
 186:	11 00                	adc    %eax,(%rax)
 188:	10 06                	adc    %al,(%rsi)
 18a:	55                   	push   %rbp
 18b:	06                   	(bad)  
 18c:	03 0e                	add    (%rsi),%ecx
 18e:	1b 0e                	sbb    (%rsi),%ecx
 190:	25 0e 13 05 00       	and    $0x5130e,%eax
	...

Disassembly of section .debug_line:

0000000000000000 <.debug_line>:
   0:	58                   	pop    %rax
   1:	00 00                	add    %al,(%rax)
   3:	00 03                	add    %al,(%rbx)
   5:	00 30                	add    %dh,(%rax)
   7:	00 00                	add    %al,(%rax)
   9:	00 01                	add    %al,(%rcx)
   b:	01 fb                	add    %edi,%ebx
   d:	0e                   	(bad)  
   e:	0d 00 01 01 01       	or     $0x1010100,%eax
  13:	01 00                	add    %eax,(%rax)
  15:	00 00                	add    %al,(%rax)
  17:	01 00                	add    %eax,(%rax)
  19:	00 01                	add    %al,(%rcx)
  1b:	2e 2e 2f             	cs cs (bad) 
  1e:	73 79                	jae    99 <_init-0x400f67>
  20:	73 64                	jae    86 <_init-0x400f7a>
  22:	65 70 73             	gs jo  98 <_init-0x400f68>
  25:	2f                   	(bad)  
  26:	78 38                	js     60 <_init-0x400fa0>
  28:	36 5f                	ss pop %rdi
  2a:	36 34 00             	ss xor $0x0,%al
  2d:	00 73 74             	add    %dh,0x74(%rbx)
  30:	61                   	(bad)  
  31:	72 74                	jb     a7 <_init-0x400f59>
  33:	2e 53                	cs push %rbx
  35:	00 01                	add    %al,(%rcx)
  37:	00 00                	add    %al,(%rax)
  39:	00 00                	add    %al,(%rax)
  3b:	09 02                	or     %eax,(%rdx)
  3d:	b0 10                	mov    $0x10,%al
  3f:	40 00 00             	add    %al,(%rax)
  42:	00 00                	add    %al,(%rax)
  44:	00 03                	add    %al,(%rbx)
  46:	3e 01 03             	add    %eax,%ds:(%rbx)
  49:	10 2e                	adc    %ch,(%rsi)
  4b:	42 23 3e             	rex.X and (%rsi),%edi
  4e:	4d 24 24             	rex.WRB and $0x24,%al
  51:	75 76                	jne    c9 <_init-0x400f37>
  53:	03 10                	add    (%rax),%edx
  55:	74 68                	je     bf <_init-0x400f41>
  57:	02 01                	add    (%rcx),%al
  59:	00 01                	add    %al,(%rcx)
  5b:	01 23                	add    %esp,(%rbx)
  5d:	00 00                	add    %al,(%rax)
  5f:	00 03                	add    %al,(%rbx)
  61:	00 1d 00 00 00 01    	add    %bl,0x1000000(%rip)        # 1000067 <_end+0xbf9f77>
  67:	01 fb                	add    %edi,%ebx
  69:	0e                   	(bad)  
  6a:	0d 00 01 01 01       	or     $0x1010100,%eax
  6f:	01 00                	add    %eax,(%rax)
  71:	00 00                	add    %al,(%rax)
  73:	01 00                	add    %eax,(%rax)
  75:	00 01                	add    %al,(%rcx)
  77:	00 69 6e             	add    %ch,0x6e(%rcx)
  7a:	69 74 2e 63 00 00 00 	imul   $0x0,0x63(%rsi,%rbp,1),%esi
  81:	00 
  82:	00 61 00             	add    %ah,0x0(%rcx)
  85:	00 00                	add    %al,(%rax)
  87:	03 00                	add    (%rax),%eax
  89:	2f                   	(bad)  
  8a:	00 00                	add    %al,(%rax)
  8c:	00 01                	add    %al,(%rcx)
  8e:	01 fb                	add    %edi,%ebx
  90:	0e                   	(bad)  
  91:	0d 00 01 01 01       	or     $0x1010100,%eax
  96:	01 00                	add    %eax,(%rax)
  98:	00 00                	add    %al,(%rax)
  9a:	01 00                	add    %eax,(%rax)
  9c:	00 01                	add    %al,(%rcx)
  9e:	2e 2e 2f             	cs cs (bad) 
  a1:	73 79                	jae    11c <_init-0x400ee4>
  a3:	73 64                	jae    109 <_init-0x400ef7>
  a5:	65 70 73             	gs jo  11b <_init-0x400ee5>
  a8:	2f                   	(bad)  
  a9:	78 38                	js     e3 <_init-0x400f1d>
  ab:	36 5f                	ss pop %rdi
  ad:	36 34 00             	ss xor $0x0,%al
  b0:	00 63 72             	add    %ah,0x72(%rbx)
  b3:	74 69                	je     11e <_init-0x400ee2>
  b5:	2e 53                	cs push %rbx
  b7:	00 01                	add    %al,(%rcx)
  b9:	00 00                	add    %al,(%rax)
  bb:	00 00                	add    %al,(%rax)
  bd:	09 02                	or     %eax,(%rdx)
  bf:	00 10                	add    %dl,(%rax)
  c1:	40 00 00             	add    %al,(%rax)
  c4:	00 00                	add    %al,(%rax)
  c6:	00 03                	add    %al,(%rbx)
  c8:	c1 00 01             	roll   $0x1,(%rax)
  cb:	4c 75 3d             	rex.WR jne 10b <_init-0x400ef5>
  ce:	2f                   	(bad)  
  cf:	02 02                	add    (%rdx),%al
  d1:	00 01                	add    %al,(%rcx)
  d3:	01 00                	add    %eax,(%rax)
  d5:	09 02                	or     %eax,(%rdx)
  d7:	54                   	push   %rsp
  d8:	19 40 00             	sbb    %eax,0x0(%rax)
  db:	00 00                	add    %al,(%rax)
  dd:	00 00                	add    %al,(%rax)
  df:	03 d3                	add    %ebx,%edx
  e1:	00 01                	add    %al,(%rcx)
  e3:	02 04 00             	add    (%rax,%rax,1),%al
  e6:	01 01                	add    %eax,(%rcx)
  e8:	f6 00 00             	testb  $0x0,(%rax)
  eb:	00 03                	add    %al,(%rbx)
  ed:	00 59 00             	add    %bl,0x0(%rcx)
  f0:	00 00                	add    %al,(%rax)
  f2:	01 01                	add    %eax,(%rcx)
  f4:	fb                   	sti    
  f5:	0e                   	(bad)  
  f6:	0d 00 01 01 01       	or     $0x1010100,%eax
  fb:	01 00                	add    %eax,(%rax)
  fd:	00 00                	add    %al,(%rax)
  ff:	01 00                	add    %eax,(%rax)
 101:	00 01                	add    %al,(%rcx)
 103:	2f                   	(bad)  
 104:	75 73                	jne    179 <_init-0x400e87>
 106:	72 2f                	jb     137 <_init-0x400ec9>
 108:	6c                   	insb   (%dx),%es:(%rdi)
 109:	69 62 36 34 2f 67 63 	imul   $0x63672f34,0x36(%rdx),%esp
 110:	63 2f                	movslq (%rdi),%ebp
 112:	78 38                	js     14c <_init-0x400eb4>
 114:	36 5f                	ss pop %rdi
 116:	36 34 2d             	ss xor $0x2d,%al
 119:	73 75                	jae    190 <_init-0x400e70>
 11b:	73 65                	jae    182 <_init-0x400e7e>
 11d:	2d 6c 69 6e 75       	sub    $0x756e696c,%eax
 122:	78 2f                	js     153 <_init-0x400ead>
 124:	31 30                	xor    %esi,(%rax)
 126:	2f                   	(bad)  
 127:	69 6e 63 6c 75 64 65 	imul   $0x6564756c,0x63(%rsi),%ebp
 12e:	00 00                	add    %al,(%rax)
 130:	65 6c                	gs insb (%dx),%es:(%rdi)
 132:	66 2d 69 6e          	sub    $0x6e69,%ax
 136:	69 74 2e 63 00 00 00 	imul   $0x0,0x63(%rsi,%rbp,1),%esi
 13d:	00 
 13e:	73 74                	jae    1b4 <_init-0x400e4c>
 140:	64 64 65 66 2e 68 00 	fs fs gs cs pushw $0x100
 147:	01 
 148:	00 00                	add    %al,(%rax)
 14a:	00 05 01 00 09 02    	add    %al,0x2090001(%rip)        # 2090151 <_end+0x1c8a061>
 150:	f0 18 40 00          	lock sbb %al,0x0(%rax)
 154:	00 00                	add    %al,(%rax)
 156:	00 00                	add    %al,(%rax)
 158:	03 c3                	add    %ebx,%eax
 15a:	00 01                	add    %al,(%rcx)
 15c:	05 03 03 0f 01       	add    $0x10f0303,%eax
 161:	05 01 06 03 71       	add    $0x71030601,%eax
 166:	01 05 28 03 12 2e    	add    %eax,0x2e120328(%rip)        # 2e120494 <_end+0x2dd1a3a4>
 16c:	05 01 03 6e 74       	add    $0x746e0301,%eax
 171:	05 28 03 12 f2       	add    $0xf2120328,%eax
 176:	05 01 03 6e 74       	add    $0x746e0301,%eax
 17b:	05 28 03 12 20       	add    $0x20120328,%eax
 180:	05 01 03 6e 3c       	add    $0x3c6e0301,%eax
 185:	05 03 03 0f 4a       	add    $0x4a0f0303,%eax
 18a:	06                   	(bad)  
 18b:	5b                   	pop    %rbx
 18c:	13 05 08 01 05 16    	adc    0x16050108(%rip),%eax        # 1605029a <_end+0x15c4a1aa>
 192:	01 05 03 06 01 4a    	add    %eax,0x4a010603(%rip)        # 4a01079b <_end+0x49c0a6ab>
 198:	05 0f 2e 05 07       	add    $0x7052e0f,%eax
 19d:	00 02                	add    %al,(%rdx)
 19f:	04 03                	add    $0x3,%al
 1a1:	06                   	(bad)  
 1a2:	59                   	pop    %rcx
 1a3:	05 08 00 02 04       	add    $0x4020008,%eax
 1a8:	03 06                	add    (%rsi),%eax
 1aa:	01 05 20 00 02 04    	add    %eax,0x4020020(%rip)        # 40201d0 <_end+0x3c1a0e0>
 1b0:	03 06                	add    (%rsi),%eax
 1b2:	c7 05 21 00 02 04 03 	movl   $0x5010603,0x4020021(%rip)        # 40201dd <_end+0x3c1a0ed>
 1b9:	06 01 05 
 1bc:	16                   	(bad)  
 1bd:	00 02                	add    %al,(%rdx)
 1bf:	04 03                	add    $0x3,%al
 1c1:	06                   	(bad)  
 1c2:	4a 05 03 00 02 04    	rex.WX add $0x4020003,%rax
 1c8:	03 06                	add    (%rsi),%eax
 1ca:	01 00                	add    %eax,(%rax)
 1cc:	02 04 03             	add    (%rbx,%rax,1),%al
 1cf:	58                   	pop    %rax
 1d0:	05 01 14 66 2e       	add    $0x2e661401,%eax
 1d5:	2e 2e 2e 06          	cs cs cs (bad) 
 1d9:	51                   	push   %rcx
 1da:	03 0a                	add    (%rdx),%ecx
 1dc:	01 02                	add    %eax,(%rdx)
 1de:	01 00                	add    %eax,(%rax)
 1e0:	01 01                	add    %eax,(%rcx)
 1e2:	5d                   	pop    %rbp
 1e3:	00 00                	add    %al,(%rax)
 1e5:	00 03                	add    %al,(%rbx)
 1e7:	00 2f                	add    %ch,(%rdi)
 1e9:	00 00                	add    %al,(%rax)
 1eb:	00 01                	add    %al,(%rcx)
 1ed:	01 fb                	add    %edi,%ebx
 1ef:	0e                   	(bad)  
 1f0:	0d 00 01 01 01       	or     $0x1010100,%eax
 1f5:	01 00                	add    %eax,(%rax)
 1f7:	00 00                	add    %al,(%rax)
 1f9:	01 00                	add    %eax,(%rax)
 1fb:	00 01                	add    %al,(%rcx)
 1fd:	2e 2e 2f             	cs cs (bad) 
 200:	73 79                	jae    27b <_init-0x400d85>
 202:	73 64                	jae    268 <_init-0x400d98>
 204:	65 70 73             	gs jo  27a <_init-0x400d86>
 207:	2f                   	(bad)  
 208:	78 38                	js     242 <_init-0x400dbe>
 20a:	36 5f                	ss pop %rdi
 20c:	36 34 00             	ss xor $0x0,%al
 20f:	00 63 72             	add    %ah,0x72(%rbx)
 212:	74 6e                	je     282 <_init-0x400d7e>
 214:	2e 53                	cs push %rbx
 216:	00 01                	add    %al,(%rcx)
 218:	00 00                	add    %al,(%rax)
 21a:	00 00                	add    %al,(%rax)
 21c:	09 02                	or     %eax,(%rdx)
 21e:	12 10                	adc    (%rax),%dl
 220:	40 00 00             	add    %al,(%rax)
 223:	00 00                	add    %al,(%rax)
 225:	00 03                	add    %al,(%rbx)
 227:	27                   	(bad)  
 228:	01 4b 02             	add    %ecx,0x2(%rbx)
 22b:	01 00                	add    %eax,(%rax)
 22d:	01 01                	add    %eax,(%rcx)
 22f:	00 09                	add    %cl,(%rcx)
 231:	02 58 19             	add    0x19(%rax),%bl
 234:	40 00 00             	add    %al,(%rax)
 237:	00 00                	add    %al,(%rax)
 239:	00 03                	add    %al,(%rbx)
 23b:	2b 01                	sub    (%rcx),%eax
 23d:	4b 02 01             	rex.WXB add (%r9),%al
 240:	00 01                	add    %al,(%rcx)
 242:	01                   	.byte 0x1

Disassembly of section .debug_str:

0000000000000000 <.debug_str>:
   0:	2e 2e 2f             	cs cs (bad) 
   3:	73 79                	jae    7e <_init-0x400f82>
   5:	73 64                	jae    6b <_init-0x400f95>
   7:	65 70 73             	gs jo  7d <_init-0x400f83>
   a:	2f                   	(bad)  
   b:	78 38                	js     45 <_init-0x400fbb>
   d:	36 5f                	ss pop %rdi
   f:	36 34 2f             	ss xor $0x2f,%al
  12:	73 74                	jae    88 <_init-0x400f78>
  14:	61                   	(bad)  
  15:	72 74                	jb     8b <_init-0x400f75>
  17:	2e 53                	cs push %rbx
  19:	00 2f                	add    %ch,(%rdi)
  1b:	68 6f 6d 65 2f       	pushq  $0x2f656d6f
  20:	61                   	(bad)  
  21:	62                   	(bad)  
  22:	75 69                	jne    8d <_init-0x400f73>
  24:	6c                   	insb   (%dx),%es:(%rdi)
  25:	64 2f                	fs (bad) 
  27:	72 70                	jb     99 <_init-0x400f67>
  29:	6d                   	insl   (%dx),%es:(%rdi)
  2a:	62                   	(bad)  
  2b:	75 69                	jne    96 <_init-0x400f6a>
  2d:	6c                   	insb   (%dx),%es:(%rdi)
  2e:	64 2f                	fs (bad) 
  30:	42 55                	rex.X push %rbp
  32:	49                   	rex.WB
  33:	4c                   	rex.WR
  34:	44 2f                	rex.R (bad) 
  36:	67 6c                	insb   (%dx),%es:(%edi)
  38:	69 62 63 2d 32 2e 33 	imul   $0x332e322d,0x63(%rdx),%esp
  3f:	31 2f                	xor    %ebp,(%rdi)
  41:	63 73 75             	movslq 0x75(%rbx),%esi
  44:	00 47 4e             	add    %al,0x4e(%rdi)
  47:	55                   	push   %rbp
  48:	20 41 53             	and    %al,0x53(%rcx)
  4b:	20 32                	and    %dh,(%rdx)
  4d:	2e 33 34 2e          	xor    %cs:(%rsi,%rbp,1),%esi
  51:	30 00                	xor    %al,(%rax)
  53:	5f                   	pop    %rdi
  54:	49                   	rex.WB
  55:	4f 5f                	rex.WRXB pop %r15
  57:	73 74                	jae    cd <_init-0x400f33>
  59:	64 69 6e 5f 75 73 65 	imul   $0x64657375,%fs:0x5f(%rsi),%ebp
  60:	64 
  61:	00 47 4e             	add    %al,0x4e(%rdi)
  64:	55                   	push   %rbp
  65:	20 43 31             	and    %al,0x31(%rbx)
  68:	31 20                	xor    %esp,(%rax)
  6a:	31 30                	xor    %esi,(%rax)
  6c:	2e 31 2e             	xor    %ebp,%cs:(%rsi)
  6f:	31 20                	xor    %esp,(%rax)
  71:	32 30                	xor    (%rax),%dh
  73:	32 30                	xor    (%rax),%dh
  75:	30 35 30 37 20 5b    	xor    %dh,0x5b203730(%rip)        # 5b2037ab <_end+0x5adfd6bb>
  7b:	72 65                	jb     e2 <_init-0x400f1e>
  7d:	76 69                	jbe    e8 <_init-0x400f18>
  7f:	73 69                	jae    ea <_init-0x400f16>
  81:	6f                   	outsl  %ds:(%rsi),(%dx)
  82:	6e                   	outsb  %ds:(%rsi),(%dx)
  83:	20 64 64 33          	and    %ah,0x33(%rsp,%riz,2)
  87:	38 36                	cmp    %dh,(%rsi)
  89:	38 36                	cmp    %dh,(%rsi)
  8b:	64 39 63 38          	cmp    %esp,%fs:0x38(%rbx)
  8f:	31 30                	xor    %esi,(%rax)
  91:	63 65 63             	movslq 0x63(%rbp),%esp
  94:	62 61                	(bad)  
  96:	61                   	(bad)  
  97:	38 30                	cmp    %dh,(%rax)
  99:	62 62                	(bad)  
  9b:	38 32                	cmp    %dh,(%rdx)
  9d:	65 64 39 31          	gs cmp %esi,%fs:(%rcx)
  a1:	63 61 61             	movslq 0x61(%rcx),%esp
  a4:	61                   	(bad)  
  a5:	35 38 61 64 36       	xor    $0x36646138,%eax
  aa:	33 35 5d 20 2d 6d    	xor    0x6d2d205d(%rip),%esi        # 6d2d210d <_end+0x6cecc01d>
  b0:	74 75                	je     127 <_init-0x400ed9>
  b2:	6e                   	outsb  %ds:(%rsi),(%dx)
  b3:	65 3d 67 65 6e 65    	gs cmp $0x656e6567,%eax
  b9:	72 69                	jb     124 <_init-0x400edc>
  bb:	63 20                	movslq (%rax),%esp
  bd:	2d 6d 61 72 63       	sub    $0x6372616d,%eax
  c2:	68 3d 78 38 36       	pushq  $0x3638783d
  c7:	2d 36 34 20 2d       	sub    $0x2d203436,%eax
  cc:	67 20 2d 67 20 2d 4f 	and    %ch,0x4f2d2067(%eip)        # 4f2d213a <_end+0x4eecc04a>
  d3:	32 20                	xor    (%rax),%ah
  d5:	2d 73 74 64 3d       	sub    $0x3d647473,%eax
  da:	67 6e                	outsb  %ds:(%esi),(%dx)
  dc:	75 31                	jne    10f <_init-0x400ef1>
  de:	31 20                	xor    %esp,(%rax)
  e0:	2d 66 67 6e 75       	sub    $0x756e6766,%eax
  e5:	38 39                	cmp    %bh,(%rcx)
  e7:	2d 69 6e 6c 69       	sub    $0x696c6e69,%eax
  ec:	6e                   	outsb  %ds:(%rsi),(%dx)
  ed:	65 20 2d 66 75 6e 77 	and    %ch,%gs:0x776e7566(%rip)        # 776e765a <_end+0x772e156a>
  f4:	69 6e 64 2d 74 61 62 	imul   $0x6261742d,0x64(%rsi),%ebp
  fb:	6c                   	insb   (%dx),%es:(%rdi)
  fc:	65 73 20             	gs jae 11f <_init-0x400ee1>
  ff:	2d 66 61 73 79       	sub    $0x79736166,%eax
 104:	6e                   	outsb  %ds:(%rsi),(%dx)
 105:	63 68 72             	movslq 0x72(%rax),%ebp
 108:	6f                   	outsl  %ds:(%rsi),(%dx)
 109:	6e                   	outsb  %ds:(%rsi),(%dx)
 10a:	6f                   	outsl  %ds:(%rsi),(%dx)
 10b:	75 73                	jne    180 <_init-0x400e80>
 10d:	2d 75 6e 77 69       	sub    $0x69776e75,%eax
 112:	6e                   	outsb  %ds:(%rsi),(%dx)
 113:	64 2d 74 61 62 6c    	fs sub $0x6c626174,%eax
 119:	65 73 20             	gs jae 13c <_init-0x400ec4>
 11c:	2d 66 73 74 61       	sub    $0x61747366,%eax
 121:	63 6b 2d             	movslq 0x2d(%rbx),%ebp
 124:	63 6c 61 73          	movslq 0x73(%rcx,%riz,2),%ebp
 128:	68 2d 70 72 6f       	pushq  $0x6f72702d
 12d:	74 65                	je     194 <_init-0x400e6c>
 12f:	63 74 69 6f          	movslq 0x6f(%rcx,%rbp,2),%esi
 133:	6e                   	outsb  %ds:(%rsi),(%dx)
 134:	20 2d 66 6d 65 72    	and    %ch,0x72656d66(%rip)        # 72656ea0 <_end+0x72250db0>
 13a:	67 65 2d 61 6c 6c 2d 	addr32 gs sub $0x2d6c6c61,%eax
 141:	63 6f 6e             	movslq 0x6e(%rdi),%ebp
 144:	73 74                	jae    1ba <_init-0x400e46>
 146:	61                   	(bad)  
 147:	6e                   	outsb  %ds:(%rsi),(%dx)
 148:	74 73                	je     1bd <_init-0x400e43>
 14a:	20 2d 66 72 6f 75    	and    %ch,0x756f7266(%rip)        # 756f73b6 <_end+0x752f12c6>
 150:	6e                   	outsb  %ds:(%rsi),(%dx)
 151:	64 69 6e 67 2d 6d 61 	imul   $0x74616d2d,%fs:0x67(%rsi),%ebp
 158:	74 
 159:	68 20 2d 66 73       	pushq  $0x73662d20
 15e:	74 61                	je     1c1 <_init-0x400e3f>
 160:	63 6b 2d             	movslq 0x2d(%rbx),%ebp
 163:	70 72                	jo     1d7 <_init-0x400e29>
 165:	6f                   	outsl  %ds:(%rsi),(%dx)
 166:	74 65                	je     1cd <_init-0x400e33>
 168:	63 74 6f 72          	movslq 0x72(%rdi,%rbp,2),%esi
 16c:	2d 73 74 72 6f       	sub    $0x6f727473,%eax
 171:	6e                   	outsb  %ds:(%rsi),(%dx)
 172:	67 20 2d 66 6d 61 74 	and    %ch,0x74616d66(%eip)        # 74616edf <_end+0x74210def>
 179:	68 2d 65 72 72       	pushq  $0x7272652d
 17e:	6e                   	outsb  %ds:(%rsi),(%dx)
 17f:	6f                   	outsl  %ds:(%rsi),(%dx)
 180:	20 2d 66 6e 6f 2d    	and    %ch,0x2d6f6e66(%rip)        # 2d6f6fec <_end+0x2d2f0efc>
 186:	73 74                	jae    1fc <_init-0x400e04>
 188:	61                   	(bad)  
 189:	63 6b 2d             	movslq 0x2d(%rbx),%ebp
 18c:	70 72                	jo     200 <_init-0x400e00>
 18e:	6f                   	outsl  %ds:(%rsi),(%dx)
 18f:	74 65                	je     1f6 <_init-0x400e0a>
 191:	63 74 6f 72          	movslq 0x72(%rdi,%rbp,2),%esi
 195:	20 2d 66 74 6c 73    	and    %ch,0x736c7466(%rip)        # 736c7601 <_end+0x732c1511>
 19b:	2d 6d 6f 64 65       	sub    $0x65646f6d,%eax
 1a0:	6c                   	insb   (%dx),%es:(%rdi)
 1a1:	3d 69 6e 69 74       	cmp    $0x74696e69,%eax
 1a6:	69 61 6c 2d 65 78 65 	imul   $0x6578652d,0x6c(%rcx),%esp
 1ad:	63 20                	movslq (%rax),%esp
 1af:	2d 66 50 49 45       	sub    $0x45495066,%eax
 1b4:	00 73 74             	add    %dh,0x74(%rbx)
 1b7:	61                   	(bad)  
 1b8:	74 69                	je     223 <_init-0x400ddd>
 1ba:	63 2d 72 65 6c 6f    	movslq 0x6f6c6572(%rip),%ebp        # 6f6c6732 <_end+0x6f2c0642>
 1c0:	63 2e                	movslq (%rsi),%ebp
 1c2:	63 00                	movslq (%rax),%eax
 1c4:	2e 2e 2f             	cs cs (bad) 
 1c7:	73 79                	jae    242 <_init-0x400dbe>
 1c9:	73 64                	jae    22f <_init-0x400dd1>
 1cb:	65 70 73             	gs jo  241 <_init-0x400dbf>
 1ce:	2f                   	(bad)  
 1cf:	78 38                	js     209 <_init-0x400df7>
 1d1:	36 5f                	ss pop %rdi
 1d3:	36 34 2f             	ss xor $0x2f,%al
 1d6:	63 72 74             	movslq 0x74(%rdx),%esi
 1d9:	69 2e 53 00 6c 6f    	imul   $0x6f6c0053,(%rsi),%ebp
 1df:	6e                   	outsb  %ds:(%rsi),(%dx)
 1e0:	67 20 6c 6f 6e       	and    %ch,0x6e(%edi,%ebp,2)
 1e5:	67 20 69 6e          	and    %ch,0x6e(%ecx)
 1e9:	74 00                	je     1eb <_init-0x400e15>
 1eb:	73 69                	jae    256 <_init-0x400daa>
 1ed:	7a 65                	jp     254 <_init-0x400dac>
 1ef:	5f                   	pop    %rdi
 1f0:	74 00                	je     1f2 <_init-0x400e0e>
 1f2:	5f                   	pop    %rdi
 1f3:	5f                   	pop    %rdi
 1f4:	69 6e 69 74 5f 61 72 	imul   $0x72615f74,0x69(%rsi),%ebp
 1fb:	72 61                	jb     25e <_init-0x400da2>
 1fd:	79 5f                	jns    25e <_init-0x400da2>
 1ff:	73 74                	jae    275 <_init-0x400d8b>
 201:	61                   	(bad)  
 202:	72 74                	jb     278 <_init-0x400d88>
 204:	00 65 6e             	add    %ah,0x6e(%rbp)
 207:	76 70                	jbe    279 <_init-0x400d87>
 209:	00 65 6c             	add    %ah,0x6c(%rbp)
 20c:	66 2d 69 6e          	sub    $0x6e69,%ax
 210:	69 74 2e 63 00 6c 6f 	imul   $0x6e6f6c00,0x63(%rsi,%rbp,1),%esi
 217:	6e 
 218:	67 20 75 6e          	and    %dh,0x6e(%ebp)
 21c:	73 69                	jae    287 <_init-0x400d79>
 21e:	67 6e                	outsb  %ds:(%esi),(%dx)
 220:	65 64 20 69 6e       	gs and %ch,%fs:0x6e(%rcx)
 225:	74 00                	je     227 <_init-0x400dd9>
 227:	5f                   	pop    %rdi
 228:	5f                   	pop    %rdi
 229:	6c                   	insb   (%dx),%es:(%rdi)
 22a:	69 62 63 5f 63 73 75 	imul   $0x7573635f,0x63(%rdx),%esp
 231:	5f                   	pop    %rdi
 232:	66 69 6e 69 00 47    	imul   $0x4700,0x69(%rsi),%bp
 238:	4e 55                	rex.WRX push %rbp
 23a:	20 43 31             	and    %al,0x31(%rbx)
 23d:	31 20                	xor    %esp,(%rax)
 23f:	31 30                	xor    %esi,(%rax)
 241:	2e 31 2e             	xor    %ebp,%cs:(%rsi)
 244:	31 20                	xor    %esp,(%rax)
 246:	32 30                	xor    (%rax),%dh
 248:	32 30                	xor    (%rax),%dh
 24a:	30 35 30 37 20 5b    	xor    %dh,0x5b203730(%rip)        # 5b203980 <_end+0x5adfd890>
 250:	72 65                	jb     2b7 <_init-0x400d49>
 252:	76 69                	jbe    2bd <_init-0x400d43>
 254:	73 69                	jae    2bf <_init-0x400d41>
 256:	6f                   	outsl  %ds:(%rsi),(%dx)
 257:	6e                   	outsb  %ds:(%rsi),(%dx)
 258:	20 64 64 33          	and    %ah,0x33(%rsp,%riz,2)
 25c:	38 36                	cmp    %dh,(%rsi)
 25e:	38 36                	cmp    %dh,(%rsi)
 260:	64 39 63 38          	cmp    %esp,%fs:0x38(%rbx)
 264:	31 30                	xor    %esi,(%rax)
 266:	63 65 63             	movslq 0x63(%rbp),%esp
 269:	62 61                	(bad)  
 26b:	61                   	(bad)  
 26c:	38 30                	cmp    %dh,(%rax)
 26e:	62 62                	(bad)  
 270:	38 32                	cmp    %dh,(%rdx)
 272:	65 64 39 31          	gs cmp %esi,%fs:(%rcx)
 276:	63 61 61             	movslq 0x61(%rcx),%esp
 279:	61                   	(bad)  
 27a:	35 38 61 64 36       	xor    $0x36646138,%eax
 27f:	33 35 5d 20 2d 6d    	xor    0x6d2d205d(%rip),%esi        # 6d2d22e2 <_end+0x6cecc1f2>
 285:	74 75                	je     2fc <_init-0x400d04>
 287:	6e                   	outsb  %ds:(%rsi),(%dx)
 288:	65 3d 67 65 6e 65    	gs cmp $0x656e6567,%eax
 28e:	72 69                	jb     2f9 <_init-0x400d07>
 290:	63 20                	movslq (%rax),%esp
 292:	2d 6d 61 72 63       	sub    $0x6372616d,%eax
 297:	68 3d 78 38 36       	pushq  $0x3638783d
 29c:	2d 36 34 20 2d       	sub    $0x2d203436,%eax
 2a1:	67 20 2d 67 20 2d 4f 	and    %ch,0x4f2d2067(%eip)        # 4f2d230f <_end+0x4eecc21f>
 2a8:	32 20                	xor    (%rax),%ah
 2aa:	2d 73 74 64 3d       	sub    $0x3d647473,%eax
 2af:	67 6e                	outsb  %ds:(%esi),(%dx)
 2b1:	75 31                	jne    2e4 <_init-0x400d1c>
 2b3:	31 20                	xor    %esp,(%rax)
 2b5:	2d 66 67 6e 75       	sub    $0x756e6766,%eax
 2ba:	38 39                	cmp    %bh,(%rcx)
 2bc:	2d 69 6e 6c 69       	sub    $0x696c6e69,%eax
 2c1:	6e                   	outsb  %ds:(%rsi),(%dx)
 2c2:	65 20 2d 66 75 6e 77 	and    %ch,%gs:0x776e7566(%rip)        # 776e782f <_end+0x772e173f>
 2c9:	69 6e 64 2d 74 61 62 	imul   $0x6261742d,0x64(%rsi),%ebp
 2d0:	6c                   	insb   (%dx),%es:(%rdi)
 2d1:	65 73 20             	gs jae 2f4 <_init-0x400d0c>
 2d4:	2d 66 61 73 79       	sub    $0x79736166,%eax
 2d9:	6e                   	outsb  %ds:(%rsi),(%dx)
 2da:	63 68 72             	movslq 0x72(%rax),%ebp
 2dd:	6f                   	outsl  %ds:(%rsi),(%dx)
 2de:	6e                   	outsb  %ds:(%rsi),(%dx)
 2df:	6f                   	outsl  %ds:(%rsi),(%dx)
 2e0:	75 73                	jne    355 <_init-0x400cab>
 2e2:	2d 75 6e 77 69       	sub    $0x69776e75,%eax
 2e7:	6e                   	outsb  %ds:(%rsi),(%dx)
 2e8:	64 2d 74 61 62 6c    	fs sub $0x6c626174,%eax
 2ee:	65 73 20             	gs jae 311 <_init-0x400cef>
 2f1:	2d 66 73 74 61       	sub    $0x61747366,%eax
 2f6:	63 6b 2d             	movslq 0x2d(%rbx),%ebp
 2f9:	63 6c 61 73          	movslq 0x73(%rcx,%riz,2),%ebp
 2fd:	68 2d 70 72 6f       	pushq  $0x6f72702d
 302:	74 65                	je     369 <_init-0x400c97>
 304:	63 74 69 6f          	movslq 0x6f(%rcx,%rbp,2),%esi
 308:	6e                   	outsb  %ds:(%rsi),(%dx)
 309:	20 2d 66 6d 65 72    	and    %ch,0x72656d66(%rip)        # 72657075 <_end+0x72250f85>
 30f:	67 65 2d 61 6c 6c 2d 	addr32 gs sub $0x2d6c6c61,%eax
 316:	63 6f 6e             	movslq 0x6e(%rdi),%ebp
 319:	73 74                	jae    38f <_init-0x400c71>
 31b:	61                   	(bad)  
 31c:	6e                   	outsb  %ds:(%rsi),(%dx)
 31d:	74 73                	je     392 <_init-0x400c6e>
 31f:	20 2d 66 72 6f 75    	and    %ch,0x756f7266(%rip)        # 756f758b <_end+0x752f149b>
 325:	6e                   	outsb  %ds:(%rsi),(%dx)
 326:	64 69 6e 67 2d 6d 61 	imul   $0x74616d2d,%fs:0x67(%rsi),%ebp
 32d:	74 
 32e:	68 20 2d 66 73       	pushq  $0x73662d20
 333:	74 61                	je     396 <_init-0x400c6a>
 335:	63 6b 2d             	movslq 0x2d(%rbx),%ebp
 338:	70 72                	jo     3ac <_init-0x400c54>
 33a:	6f                   	outsl  %ds:(%rsi),(%dx)
 33b:	74 65                	je     3a2 <_init-0x400c5e>
 33d:	63 74 6f 72          	movslq 0x72(%rdi,%rbp,2),%esi
 341:	2d 73 74 72 6f       	sub    $0x6f727473,%eax
 346:	6e                   	outsb  %ds:(%rsi),(%dx)
 347:	67 20 2d 66 6d 61 74 	and    %ch,0x74616d66(%eip)        # 746170b4 <_end+0x74210fc4>
 34e:	68 2d 65 72 72       	pushq  $0x7272652d
 353:	6e                   	outsb  %ds:(%rsi),(%dx)
 354:	6f                   	outsl  %ds:(%rsi),(%dx)
 355:	20 2d 66 6e 6f 2d    	and    %ch,0x2d6f6e66(%rip)        # 2d6f71c1 <_end+0x2d2f10d1>
 35b:	73 74                	jae    3d1 <_init-0x400c2f>
 35d:	61                   	(bad)  
 35e:	63 6b 2d             	movslq 0x2d(%rbx),%ebp
 361:	70 72                	jo     3d5 <_init-0x400c2b>
 363:	6f                   	outsl  %ds:(%rsi),(%dx)
 364:	74 65                	je     3cb <_init-0x400c35>
 366:	63 74 6f 72          	movslq 0x72(%rdi,%rbp,2),%esi
 36a:	20 2d 66 50 49 43    	and    %ch,0x43495066(%rip)        # 434953d6 <_end+0x4308f2e6>
 370:	20 2d 66 73 74 61    	and    %ch,0x61747366(%rip)        # 617476dc <_end+0x613415ec>
 376:	63 6b 2d             	movslq 0x2d(%rbx),%ebp
 379:	70 72                	jo     3ed <_init-0x400c13>
 37b:	6f                   	outsl  %ds:(%rsi),(%dx)
 37c:	74 65                	je     3e3 <_init-0x400c1d>
 37e:	63 74 6f 72          	movslq 0x72(%rdi,%rbp,2),%esi
 382:	2d 73 74 72 6f       	sub    $0x6f727473,%eax
 387:	6e                   	outsb  %ds:(%rsi),(%dx)
 388:	67 20 2d 66 74 6c 73 	and    %ch,0x736c7466(%eip)        # 736c77f5 <_end+0x732c1705>
 38f:	2d 6d 6f 64 65       	sub    $0x65646f6d,%eax
 394:	6c                   	insb   (%dx),%es:(%rdi)
 395:	3d 69 6e 69 74       	cmp    $0x74696e69,%eax
 39a:	69 61 6c 2d 65 78 65 	imul   $0x6578652d,0x6c(%rcx),%esp
 3a1:	63 00                	movslq (%rax),%eax
 3a3:	63 68 61             	movslq 0x61(%rax),%ebp
 3a6:	72 00                	jb     3a8 <_init-0x400c58>
 3a8:	61                   	(bad)  
 3a9:	72 67                	jb     412 <_init-0x400bee>
 3ab:	63 00                	movslq (%rax),%eax
 3ad:	73 69                	jae    418 <_init-0x400be8>
 3af:	7a 65                	jp     416 <_init-0x400bea>
 3b1:	00 5f 5f             	add    %bl,0x5f(%rdi)
 3b4:	6c                   	insb   (%dx),%es:(%rdi)
 3b5:	69 62 63 5f 63 73 75 	imul   $0x7573635f,0x63(%rdx),%esp
 3bc:	5f                   	pop    %rdi
 3bd:	69 6e 69 74 00 61 72 	imul   $0x72610074,0x69(%rsi),%ebp
 3c4:	67 76 00             	addr32 jbe 3c7 <_init-0x400c39>
 3c7:	6c                   	insb   (%dx),%es:(%rdi)
 3c8:	6f                   	outsl  %ds:(%rsi),(%dx)
 3c9:	6e                   	outsb  %ds:(%rsi),(%dx)
 3ca:	67 20 64 6f 75       	and    %ah,0x75(%edi,%ebp,2)
 3cf:	62                   	(bad)  
 3d0:	6c                   	insb   (%dx),%es:(%rdi)
 3d1:	65 00 5f 5f          	add    %bl,%gs:0x5f(%rdi)
 3d5:	69 6e 69 74 5f 61 72 	imul   $0x72615f74,0x69(%rsi),%ebp
 3dc:	72 61                	jb     43f <_init-0x400bc1>
 3de:	79 5f                	jns    43f <_init-0x400bc1>
 3e0:	65 6e                	outsb  %gs:(%rsi),(%dx)
 3e2:	64 00 2e             	add    %ch,%fs:(%rsi)
 3e5:	2e 2f                	cs (bad) 
 3e7:	73 79                	jae    462 <_init-0x400b9e>
 3e9:	73 64                	jae    44f <_init-0x400bb1>
 3eb:	65 70 73             	gs jo  461 <_init-0x400b9f>
 3ee:	2f                   	(bad)  
 3ef:	78 38                	js     429 <_init-0x400bd7>
 3f1:	36 5f                	ss pop %rdi
 3f3:	36 34 2f             	ss xor $0x2f,%al
 3f6:	63 72 74             	movslq 0x74(%rdx),%esi
 3f9:	6e                   	outsb  %ds:(%rsi),(%dx)
 3fa:	2e 53                	cs push %rbx
	...

Disassembly of section .debug_loc:

0000000000000000 <.debug_loc>:
	...
   c:	00 00                	add    %al,(%rax)
   e:	2c 00                	sub    $0x0,%al
  10:	00 00                	add    %al,(%rax)
  12:	00 00                	add    %al,(%rax)
  14:	00 00                	add    %al,(%rax)
  16:	01 00                	add    %eax,(%rax)
  18:	55                   	push   %rbp
  19:	2c 00                	sub    $0x0,%al
  1b:	00 00                	add    %al,(%rax)
  1d:	00 00                	add    %al,(%rax)
  1f:	00 00                	add    %al,(%rax)
  21:	56                   	push   %rsi
  22:	00 00                	add    %al,(%rax)
  24:	00 00                	add    %al,(%rax)
  26:	00 00                	add    %al,(%rax)
  28:	00 01                	add    %al,(%rcx)
  2a:	00 5c 56 00          	add    %bl,0x0(%rsi,%rdx,2)
  2e:	00 00                	add    %al,(%rax)
  30:	00 00                	add    %al,(%rax)
  32:	00 00                	add    %al,(%rax)
  34:	5d                   	pop    %rbp
  35:	00 00                	add    %al,(%rax)
  37:	00 00                	add    %al,(%rax)
  39:	00 00                	add    %al,(%rax)
  3b:	00 04 00             	add    %al,(%rax,%rax,1)
  3e:	f3 01 55 9f          	repz add %edx,-0x61(%rbp)
	...
  5e:	00 00                	add    %al,(%rax)
  60:	2c 00                	sub    $0x0,%al
  62:	00 00                	add    %al,(%rax)
  64:	00 00                	add    %al,(%rax)
  66:	00 00                	add    %al,(%rax)
  68:	01 00                	add    %eax,(%rax)
  6a:	54                   	push   %rsp
  6b:	2c 00                	sub    $0x0,%al
  6d:	00 00                	add    %al,(%rax)
  6f:	00 00                	add    %al,(%rax)
  71:	00 00                	add    %al,(%rax)
  73:	58                   	pop    %rax
  74:	00 00                	add    %al,(%rax)
  76:	00 00                	add    %al,(%rax)
  78:	00 00                	add    %al,(%rax)
  7a:	00 01                	add    %al,(%rcx)
  7c:	00 5d 58             	add    %bl,0x58(%rbp)
  7f:	00 00                	add    %al,(%rax)
  81:	00 00                	add    %al,(%rax)
  83:	00 00                	add    %al,(%rax)
  85:	00 5d 00             	add    %bl,0x0(%rbp)
  88:	00 00                	add    %al,(%rax)
  8a:	00 00                	add    %al,(%rax)
  8c:	00 00                	add    %al,(%rax)
  8e:	04 00                	add    $0x0,%al
  90:	f3 01 54 9f 00       	repz add %edx,0x0(%rdi,%rbx,4)
	...
  b1:	00 2c 00             	add    %ch,(%rax,%rax,1)
  b4:	00 00                	add    %al,(%rax)
  b6:	00 00                	add    %al,(%rax)
  b8:	00 00                	add    %al,(%rax)
  ba:	01 00                	add    %eax,(%rax)
  bc:	51                   	push   %rcx
  bd:	2c 00                	sub    $0x0,%al
  bf:	00 00                	add    %al,(%rax)
  c1:	00 00                	add    %al,(%rax)
  c3:	00 00                	add    %al,(%rax)
  c5:	5a                   	pop    %rdx
  c6:	00 00                	add    %al,(%rax)
  c8:	00 00                	add    %al,(%rax)
  ca:	00 00                	add    %al,(%rax)
  cc:	00 01                	add    %al,(%rcx)
  ce:	00 5e 5a             	add    %bl,0x5a(%rsi)
  d1:	00 00                	add    %al,(%rax)
  d3:	00 00                	add    %al,(%rax)
  d5:	00 00                	add    %al,(%rax)
  d7:	00 5d 00             	add    %bl,0x0(%rbp)
  da:	00 00                	add    %al,(%rax)
  dc:	00 00                	add    %al,(%rax)
  de:	00 00                	add    %al,(%rax)
  e0:	04 00                	add    $0x0,%al
  e2:	f3 01 51 9f          	repz add %edx,-0x61(%rcx)
	...
  f6:	01 00                	add    %eax,(%rax)
  f8:	00 00                	add    %al,(%rax)
  fa:	2d 00 00 00 00       	sub    $0x0,%eax
  ff:	00 00                	add    %al,(%rax)
 101:	00 31                	add    %dh,(%rcx)
 103:	00 00                	add    %al,(%rax)
 105:	00 00                	add    %al,(%rax)
 107:	00 00                	add    %al,(%rax)
 109:	00 05 00 76 00 33    	add    %al,0x33007600(%rip)        # 3300770f <_end+0x32c0161f>
 10f:	26 9f                	es lahf 
 111:	31 00                	xor    %eax,(%rax)
 113:	00 00                	add    %al,(%rax)
 115:	00 00                	add    %al,(%rax)
 117:	00 00                	add    %al,(%rax)
 119:	54                   	push   %rsp
 11a:	00 00                	add    %al,(%rax)
 11c:	00 00                	add    %al,(%rax)
 11e:	00 00                	add    %al,(%rax)
 120:	00 01                	add    %al,(%rcx)
 122:	00 56 00             	add    %dl,0x0(%rsi)
	...
 131:	00 00                	add    %al,(%rax)
 133:	00 03                	add    %al,(%rbx)
 135:	00 00                	add    %al,(%rax)
 137:	00 2d 00 00 00 00    	add    %ch,0x0(%rip)        # 13d <_init-0x400ec3>
 13d:	00 00                	add    %al,(%rax)
 13f:	00 35 00 00 00 00    	add    %dh,0x0(%rip)        # 145 <_init-0x400ebb>
 145:	00 00                	add    %al,(%rax)
 147:	00 02                	add    %al,(%rdx)
 149:	00 30                	add    %dh,(%rax)
 14b:	9f                   	lahf   
 14c:	35 00 00 00 00       	xor    $0x0,%eax
 151:	00 00                	add    %al,(%rax)
 153:	00 4e 00             	add    %cl,0x0(%rsi)
 156:	00 00                	add    %al,(%rax)
 158:	00 00                	add    %al,(%rax)
 15a:	00 00                	add    %al,(%rax)
 15c:	01 00                	add    %eax,(%rax)
 15e:	53                   	push   %rbx
	...

Disassembly of section .debug_ranges:

0000000000000000 <.debug_ranges>:
   0:	ff                   	(bad)  
   1:	ff                   	(bad)  
   2:	ff                   	(bad)  
   3:	ff                   	(bad)  
   4:	ff                   	(bad)  
   5:	ff                   	(bad)  
   6:	ff                   	(bad)  
   7:	ff 00                	incl   (%rax)
	...
  11:	10 40 00             	adc    %al,0x0(%rax)
  14:	00 00                	add    %al,(%rax)
  16:	00 00                	add    %al,(%rax)
  18:	12 10                	adc    (%rax),%dl
  1a:	40 00 00             	add    %al,(%rax)
  1d:	00 00                	add    %al,(%rax)
  1f:	00 54 19 40          	add    %dl,0x40(%rcx,%rbx,1)
  23:	00 00                	add    %al,(%rax)
  25:	00 00                	add    %al,(%rax)
  27:	00 58 19             	add    %bl,0x19(%rax)
  2a:	40 00 00             	add    %al,(%rax)
	...
  3d:	00 00                	add    %al,(%rax)
  3f:	00 ff                	add    %bh,%bh
  41:	ff                   	(bad)  
  42:	ff                   	(bad)  
  43:	ff                   	(bad)  
  44:	ff                   	(bad)  
  45:	ff                   	(bad)  
  46:	ff                   	(bad)  
  47:	ff 00                	incl   (%rax)
  49:	00 00                	add    %al,(%rax)
  4b:	00 00                	add    %al,(%rax)
  4d:	00 00                	add    %al,(%rax)
  4f:	00 12                	add    %dl,(%rdx)
  51:	10 40 00             	adc    %al,0x0(%rax)
  54:	00 00                	add    %al,(%rax)
  56:	00 00                	add    %al,(%rax)
  58:	17                   	(bad)  
  59:	10 40 00             	adc    %al,0x0(%rax)
  5c:	00 00                	add    %al,(%rax)
  5e:	00 00                	add    %al,(%rax)
  60:	58                   	pop    %rax
  61:	19 40 00             	sbb    %eax,0x0(%rax)
  64:	00 00                	add    %al,(%rax)
  66:	00 00                	add    %al,(%rax)
  68:	5d                   	pop    %rbp
  69:	19 40 00             	sbb    %eax,0x0(%rax)
	...
