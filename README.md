# PHP Magic Hashes Open MPI
Copyright 2021 Maxim Masiutin <maxim@masitin.com>  
All rights reserved  

Version 1.0.  
May 28th, 2021.  

An Open MPI application to look for PHP Magic Hashes using distributed computing.  
It hashes multiple messages with SHA-1 until a hash is found that matches the definition of a PHP Magic Hash.  
A PHP magic hash is a hash that in hexadecimal form starts with 0e and then has only decimal digits, e.g., 0e26379374770352024666148968868586665768.  
See the "phpmagic_sha1.php" file for some of the messages found that produce PHP Magic Hashes if hashed with SHA-1. Here are a few of such hashes.  

```
1023456852390915        0e26379374770352024666148968868586665768
lowercasegzmgqmx        0e46257280787231943618306073689855362607
lowercasifdvqkfr        0e11372668415308535558155136274413213182
lowercasebchqcwctky     0e63270019212961791900055698786302314274
lowercaseabcsobpkrt     0e54706107047262165256262457226759421225
UPPERCASFFLIIQWR        00e0209539108131630074694125235505223102
MixedCaseERWqTVQ        0e26765837881628507475765845815158037783
MixCaseDigJiRR9d        00e6970695351422324349039381794949865825
Punctuati0t..jsI        0e77237948969014118794910091659528041921
Punc!0"*!"#$8!zv        0e77726009946581613829608157794165640009
UTM!1k345678fNzG        0e60098992377811189363030093264003550414
Maxim!3M3457WL8N        0e56563987203581868006812012373581596907
SI201M!2M34FUN"s        0e56771164582932122522008085807868856600
Punctu!U"F5ru   	0e10005769841271999406141555258742283712
Punc!0!v!%X&H   	0e46022419093253497711357929642317161144
Punc!0"5!%N/J/  	0e23361421882052104970353750698818490573
Punc!0"/!"#Z"f# 	0e62673103166046521233198723999648604397
Punctuatiow$'l9X        0e16039695246683143323677708220808911326
Anastasia!$3j6CE        0e39502544098047582971721681103284862230
Anastasia"D#L3R"        0e38695756209930671587956403047252377646
```

The Open MPI interface allows looking for a the PHP Magic Hash in parallel, using multiple different distributed processors.  
The application should be individually compiled on each target processor to take the benefits of these particular processors (optimizations, instruction sets, SHA-1 CPU instructions, if available, etc.). You can use tools like Ansible to automate the tasks.  
Although GPUs calculate hashes very quickly, this application can be useful for clusters which have no GPU but have computing time available.  
For example, on 14 servers with a total of 106 cores of various processors manufactured between 2014 and 2017, some of which support SHA-1 CPU instructions and some not, with a combined Passmark CPU mark of 111706, it usually takes 2-10 seconds to find a PHP Magic Hash.  

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.  
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.  
You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>  

SHA1 implementation using the CPU instructions (sha1msg1, sha1msg2, sha1rnds4, sha1nexte) is written by Jeffrey Walton.  
Taken from the Jeffrey Walton's (noloader) GitHub page at <https://github.com/noloader/SHA-Intrinsics/blob/master/sha1-x86.c>  

SHA1 implementation using the pure C (when no the CPU is not equipped with the SHA instructions) is written by Steve Reid.  
Taken from the "clibs" GitHub page at <https://github.com/clibs/sha1>  

# Compiling

Just run `.\compile.sh`. Modify this file accordingly, if needed.

# Configuring 

Look for the configuration section in the `phpmagic_sha1_openmpi.cpp`. You can specify whether you need a digits-only message, lowercase, uppercase, mixed-case, the mixed case with digits, or mixed case with digits and punctuation characters.  
Also, look for `std::string message` to specify a prefix to your message. You can set an empty prefix.  

# Running

Use `mpirun phpmagic_sha1_openmpi` or the other method. You may use any way that you use to run Open MPI applications.  
