import std.stdio;
import std.string;
import std.file;
import std.algorithm;
import std.array;
import core.sys.windows.windows;
import core.sys.windows.winbase;
import core.sys.windows.winnt;

struct Pe {
    void* imageBase;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS64 ntHeaders;
    PIMAGE_EXPORT_DIRECTORY exportDirectory;
}

Pe parsePeImage(string imageName) {
    void* imageBase = LoadLibraryA(imageName.toStringz());
    if (imageBase is null) {
        writeln("Error: Could not load image: ", imageName);
        return Pe(null, null, null, null);
    }

    ulong peBase = cast(ulong)imageBase;
    PIMAGE_DOS_HEADER dosHeader = cast(PIMAGE_DOS_HEADER)imageBase;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        writeln("Error: Invalid DOS header.");
        return Pe(null, null, null, null);
    }

    if (dosHeader.e_lfanew == 0) {
        writeln("Error: e_lfanew is 0, invalid PE header.");
        return Pe(null, null, null, null);
    }

    PIMAGE_NT_HEADERS64 ntHeaders = cast(PIMAGE_NT_HEADERS64)(peBase + dosHeader.e_lfanew);

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        writeln("Error: Invalid NT header signature.");
        return Pe(null, null, null, null);
    }

    PIMAGE_OPTIONAL_HEADER64 optionalHeader = &ntHeaders.OptionalHeader;

    if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        writeln("No export directory found.");
        return Pe(null, null, null, null);
    }

    ulong exportDirAddr = peBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = cast(PIMAGE_EXPORT_DIRECTORY)exportDirAddr;

    return Pe(imageBase, dosHeader, ntHeaders, exportDirectory);
}

string readStringFromMemory(ulong addr) {
    string result;
    ulong currentAddr = addr;

    while (true) {
        ubyte byteVal = *cast(ubyte*)currentAddr;
        if (byteVal == 0) break;
        result ~= cast(char)byteVal;
        currentAddr++;
    }

    return result;
}

uint extractSSN(void* fnAddr) {
    ulong cw = 0;

    while (true) {
        if (*(cast(ubyte*)fnAddr + cw) == 0xE9) {
            return 0;
        }

        if (*(cast(ubyte*)fnAddr + cw) == 0xB8) {
            uint ssn = *(cast(uint*)(fnAddr + cw + 1));
            return ssn;
        }

        cw++;
    }
}

struct SystemCall {
    string fnName;
    uint ssn;
    ulong addr;
}

SystemCall[] getSystemCalls(string imageName) {
    Pe peImage = parsePeImage(imageName);

    if (peImage.imageBase is null || peImage.exportDirectory is null) {
        return [];
    }

    auto exportDirectory = peImage.exportDirectory;
    ulong peBase = cast(ulong)peImage.imageBase;

    uint* funcNames = cast(uint*)(peBase + exportDirectory.AddressOfNames);
    uint* funcAddrs = cast(uint*)(peBase + exportDirectory.AddressOfFunctions);
    ushort* funcNameOrds = cast(ushort*)(peBase + exportDirectory.AddressOfNameOrdinals);

    SystemCall[] systemCalls;

    foreach (i; 0 .. exportDirectory.NumberOfNames) {
        string fnName = readStringFromMemory(peBase + funcNames[i]);

        if (fnName.startsWith("Zw")) {
            uint fnOrd = funcNameOrds[i];
            uint fnRva = funcAddrs[fnOrd];

            void* fnAddr = cast(void*)(peBase + fnRva);

            uint ssn = extractSSN(fnAddr);
            systemCalls ~= SystemCall(fnName, ssn, cast(ulong)fnAddr);
        }
    }

    return systemCalls;
}

void main(string[] args) {
    if (args.length < 2) {
        writeln("Usage: <OUTPUT_FILE> [OPTIONAL_ROUTINE]");
        return;
    }

    string outputFile = args[1];
    string specificRoutine;
    bool dumpToFile = true;

    if (args.length > 2) {
        specificRoutine = args[2];
        dumpToFile = false;  
    }

    auto systemCalls = getSystemCalls("C:\\Windows\\System32\\ntoskrnl.exe");

    if (systemCalls.length == 0) {
        writeln("No system calls found.");
        return;
    }

    if (specificRoutine.length > 0) {
        auto result = systemCalls.filter!(sc => sc.fnName == specificRoutine).array;
        if (result.length == 0) {
            writeln("Routine not found: ", specificRoutine);
        } else {
            auto sc = result[0];
            writeln(sc.fnName, " ~> 0x", format("%X", sc.addr));
            writeln("SSN: ", sc.ssn);
        }
    } else {
        auto outputLines = systemCalls.map!(sc => 
            "[+] " ~ sc.fnName ~ ": SSN=0x" ~ format("%X", sc.ssn) ~ 
            " ~> Address: 0x" ~ format("%X", sc.addr)
        ).array;

        writeln("Dumped ", outputLines.length, " Kernel Routines.");

        if (dumpToFile) {
            outputLines.join("\n").toFile(outputFile);
            writeln("Output saved to: ", outputFile);
        } else {
            foreach (line; outputLines) {
                writeln(line);
            }
        }
    }
}