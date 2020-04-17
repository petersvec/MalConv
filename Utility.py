import os
import argparse
import pefile
import peutils
import PackerDetection

parser = argparse.ArgumentParser(description = "Utility for malware detection system dataset creation")
parser.add_argument("--benign", action = 'store_true')
parser.add_argument("--malware", action = 'store_true')
parser.add_argument("--path", type = str, default = "C:\\")

'''
    Checks if file is in correct format(PE) and architecture(x86)
    path -> executable path
'''
def check_pe(path):
    try:
        pe = pefile.PE(path)

        signature = hex(pe.NT_HEADERS.Signature)
        machine = hex(pe.FILE_HEADER.Machine)

        if signature == '0x4550' and machine == '0x14c':
            return True
    except OSError as e:
        return False
    except pefile.PEFormatError as e:
        return False

    return False

'''
    Creates csv file with labels + checks for correctness of PE file (if it is an x86 executable file)
    path -> location of executables
'''
def benign_creation(path):
    paths = []

    for dirpath, dirs, files in os.walk(path):
        for filename in files:
            if filename.endswith(".exe") or filename.endswith(".dll"):
                fname = os.path.join(dirpath, filename)
                
                if check_pe(fname):
                    print("Found: " + fname)
                    paths.append(fname)

    with open("benign_labels.csv", 'w') as f:
        for file in paths:
            f.write(file + ', 1\n')

'''
    Creates csv file with labels + checks for correctnes of the malware sample (x86, unpacked)
    path -> location of executables
    signatures -> PEID signatres database
'''
def malware_creation(path, signatures):
    paths = []

    for dirpath, dirs, files in os.walk(path):
        for filename in files:
            fname = os.path.join(dirpath, filename)

            if check_pe(fname) and PackerDetection.check(fname, signatures) == False:
                print("Correct sample: " + fname)
                paths.append(fname)

    with open("malware_labels.csv", 'w') as f:
        for file in paths:
            f.write(file + ', 0\n')


if __name__ == '__main__':
    args = parser.parse_args()

    if args.benign:
        benign_creation(args.path)

    if args.malware:
        signatures = peutils.SignatureDatabase("packers.txt")
        malware_creation(args.path, signatures)