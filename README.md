# yara-fileheader-condition
After checking lots of third party yara rule. Most company will add hex value in certain file offset or memory virtual address. Adding those accessing data at a given position provide not only  the false alert when scanning infected machine but also identify binary file type.

## yara rule document 
Based on yara document, we don't need to import any extend libarary to use this signed integers and unsigned integers fucntion to read the 8, 16, and 32 bits from offset or virtual address.  
Both 16 and 32 bits integer are considered to be little-endian. Big-endian integer use the corresponding function ending in **be**.
- Int16 -- (-32,768 to +32,767) : 2 bytes
- Int32 -- (-2,147,483,648 to +2,147,483,647) : 4 bytes
```
int8(<offset or virtual address>)
int16(<offset or virtual address>)
int32(<offset or virtual address>)

uint8(<offset or virtual address>)
uint16(<offset or virtual address>)
uint32(<offset or virtual address>)

int8be(<offset or virtual address>)
int16be(<offset or virtual address>)
int32be(<offset or virtual address>)

uint8be(<offset or virtual address>)
uint16be(<offset or virtual address>)
uint32be(<offset or virtual address>)
```

## compiler signatures
The compiler signature is based on the PE file structure. With the yara signed integers and unsigned integers fucntion we can easily to write some PE signature in our yara rules. 

- MZ, PE, ELF, etc signature
- Is it dll, console version, windows GUI version etc.
- Checking export table import table etc.
```
// MZ signature at offset 0 
uint16(0) == 0x5A4D

// PE signature at offset 3C 
(uint32(uint32(0x3C)) == 0x00004550)

// PE signature at offset stored in MZ header at 0x3C
uint16(uint32(0x3C)+0x18) == 0x010B  //PE 32 bits
uint16(uint32(0x3C)+0x18) == 0x020B  //PE 64 bits
uint16(uint32(0x3C)+0x18) == 0x0107  //ROM

//Export_Table_RVA+Export_Data_Size .. cannot be outside imagesize
((uint32(uint32(0x3C)+0x78+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x7C+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)))) > (uint32(uint32(0x3C)+0x50))
```

## reference
https://github.com/x64dbg/yarasigs/blob/master/packer_compiler_signatures.yara
https://yara.readthedocs.io/en/v3.4.0/writingrules.html#conditions