import gzip
from glob import glob
import sys
from pathlib import Path
import os

def create_gz(input_path:str)->bytes:
    with open(input_path, "rb") as fp:
        return gzip.compress(fp.read())

def main():
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    for p in glob(f"{input_dir}/**"):
        output = Path(output_dir + p.removeprefix(input_dir))
        print(f"compressing {p} -> {output}.gz")
        if not os.path.exists(output.parent):
            os.makedirs(output.parent, exist_ok=True)
        with open(str(output) + ".gz", "wb") as fp:
            fp.write(create_gz(p))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(sys.argv)
        print(f'usage: {sys.argv[0]} <original folder> <output folder>')
        exit(-1)
    main()