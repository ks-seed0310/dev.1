# tools/analyze_exe.py
import sys
import pefile
import subprocess

def dump_pe_info(path, out):
    pe = pefile.PE(path)
    out.write(f"File: {path}\n")
    out.write(f"Machine: {hex(pe.FILE_HEADER.Machine)}\n")
    out.write(f"NumberOfSections: {pe.FILE_HEADER.NumberOfSections}\n")
    out.write(f"TimeDateStamp: {pe.FILE_HEADER.TimeDateStamp}\n")
    out.write(f"EntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n")
    out.write(f"ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}\n")
    out.write("\nSections:\n")
    for s in pe.sections:
        out.write(f"  {s.Name.decode(errors='ignore').rstrip(chr(0))}  VirtualSize={hex(s.Misc_VirtualSize)}  SizeOfRawData={hex(s.SizeOfRawData)}\n")
    out.write("\nImports:\n")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            out.write(f"  {entry.dll.decode(errors='ignore')}\n")
            for imp in entry.imports:
                out.write(f"    {imp.name}\n")
    else:
        out.write("  (no imports found)\n")
    out.write("\nResources (types):\n")
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for res in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                out.write(f"  type: {res.struct.Id}\n")
    except Exception as e:
        out.write(f"  resource parse error: {e}\n")

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print("Usage: analyze_exe.py <exe> <out_report> <out_strings>")
        sys.exit(1)
    exe = sys.argv[1]
    rpt = sys.argv[2]
    sfile = sys.argv[3]
    with open(rpt, "w", encoding="utf-8", errors="replace") as out:
        try:
            dump_pe_info(exe, out)
        except Exception as e:
            out.write("PE parse error: " + str(e) + "\n")
    # run strings
    try:
        with open(sfile, "wb") as s:
            proc = subprocess.run(["strings", "-a", exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            s.write(proc.stdout)
    except Exception as e:
        with open(sfile, "w", encoding="utf-8", errors="replace") as s:
            s.write("strings error: " + str(e))
