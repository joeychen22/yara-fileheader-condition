import "pe"
import "math"

rule IsPE32 : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
        //PE signature at offset 3C and ...
        (uint32(uint32(0x3C)) == 0x00004550) and 
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x18) == 0x010B
}

rule IsPE64 : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
        //PE signature at offset 3C and ...
        (uint32(uint32(0x3C)) == 0x00004550) and 
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x18) == 0x020B
}